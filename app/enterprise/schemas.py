"""企业实名开通资料模型与敏感声明（同文件维护，随资料版本同步生效）。

关键约定：

* **模型与声明同处一个文件**：资料版本新增字段时，在 Pydantic 模型与
  :data:`ONBOARDING_POLICY` 声明树中同步增加即可——日志脱敏、422 错误明细、
  下游调用记录、脱敏审计立即对新字段生效，**无需改动任何公共配置文件**；
* 字段接受多种写法：Python 字段名（下划线）经 ``AliasChoices`` 同时接受
  camelCase/连字符等请求写法；脱敏侧 :func:`normalize_key` 做同样的归一；
* 同一字段名在不同子结构中可有不同敏感级别，声明路径决定判定
  （例：``contact.name`` 是个人姓名 → 掩码；``attachment.name`` 是文件名 → 保留）；
* 联系人 ``contacts``、证件 ``id_documents``、附件 ``attachments`` 均为数组，
  每条资料都按同一份子声明判定，不遗漏。
"""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, BaseModel, Field

from app.observability.sensitive import (
    CAT_BUSINESS,
    CAT_CONTACT,
    CAT_FINANCE,
    CAT_ID_NUMBER,
    CAT_NAME,
    SensitivePolicy,
    build_policy,
    group,
    leaf,
    many,
    plain,
)

#: 场景名（低基数，进入日志/指标时不随字段增长）。
PROFILE_NAME = "enterprise_onboarding"


# ---------------------------------------------------------------------------
# 资料模型（多层嵌套 / 数组 / 别名 / 可选分支）
# ---------------------------------------------------------------------------
class IdDocument(BaseModel):
    """单个证件：证件类型 + 证件号 + 可选证件影像附件 ID。"""

    doc_type: Literal["id_card", "passport", "uscc", "other"] = Field(
        validation_alias=AliasChoices("doc_type", "docType", "doc-type")
    )
    doc_number: str = Field(
        min_length=6,
        max_length=32,
        validation_alias=AliasChoices("doc_number", "docNumber", "doc-number", "cert_no", "certNo"),
    )
    image_id: str | None = Field(
        default=None,
        max_length=64,
        validation_alias=AliasChoices("image_id", "imageId", "image-id"),
    )


class Contact(BaseModel):
    """多层联系人之一：姓名、角色、手机号/邮箱（可选分支）、多个证件。"""

    name: str = Field(
        min_length=1,
        max_length=64,
        validation_alias=AliasChoices("name", "contact_name", "contactName"),
    )
    role: Literal["legal_rep", "operator", "finance"] = Field(
        validation_alias=AliasChoices("role", "contact_role", "contactRole")
    )
    mobile: str = Field(
        min_length=5,
        max_length=20,
        validation_alias=AliasChoices("mobile", "phone", "phoneNumber", "phone_number"),
    )
    email: str | None = Field(
        default=None,
        max_length=128,
        validation_alias=AliasChoices("email", "mail", "emailAddress", "email_address"),
    )
    id_documents: list[IdDocument] | None = Field(
        default=None,
        max_length=10,
        validation_alias=AliasChoices("id_documents", "idDocuments", "id-documents"),
    )


class Attachment(BaseModel):
    """资料附件：文件名非敏感（前端需要回显提示），影像 file_id 为业务标识。"""

    name: str = Field(
        min_length=1,
        max_length=256,
        validation_alias=AliasChoices("name", "file_name", "fileName"),
    )
    file_id: str = Field(
        min_length=8,
        max_length=64,
        validation_alias=AliasChoices(
            "file_id", "fileId", "file-id", "oss_key", "ossKey", "oss-key"
        ),
    )


class BankAccount(BaseModel):
    """可选结算账户（可选分支）：账户名/开户行非个人标识，银行账号敏感。"""

    account_name: str = Field(
        min_length=1,
        max_length=128,
        validation_alias=AliasChoices("account_name", "accountName"),
    )
    bank_name: str = Field(
        min_length=1,
        max_length=128,
        validation_alias=AliasChoices("bank_name", "bankName"),
    )
    account_number: str = Field(
        min_length=8,
        max_length=32,
        validation_alias=AliasChoices("account_number", "accountNumber", "bank_card", "bankCard"),
    )


class EnterpriseOnboardingRequest(BaseModel):
    """企业实名开通请求体。"""

    profile_version: str = Field(
        default="1",
        min_length=1,
        max_length=16,
        validation_alias=AliasChoices("profile_version", "profileVersion"),
    )
    enterprise_name: str = Field(
        min_length=2,
        max_length=128,
        validation_alias=AliasChoices("enterprise_name", "enterpriseName", "corp_name", "corpName"),
    )
    unified_social_credit_code: str = Field(
        min_length=8,
        max_length=32,
        pattern=r"^[0-9A-Za-z*]+$",
        validation_alias=AliasChoices(
            "unified_social_credit_code", "unifiedSocialCreditCode",
            "credit_code", "creditCode",
        ),
    )
    industry: Literal["it", "finance", "manufacturing", "services", "other"] = Field(
        validation_alias=AliasChoices("industry", "industry_type", "industryType")
    )
    contacts: list[Contact] = Field(min_length=1, max_length=20)
    attachments: list[Attachment] | None = Field(
        default=None,
        max_length=50,
        validation_alias=AliasChoices("attachments", "files"),
    )
    bank_account: BankAccount | None = Field(
        default=None,
        validation_alias=AliasChoices("bank_account", "bankAccount"),
    )
    remark: str | None = Field(default=None, max_length=512)

    model_config = {"populate_by_name": True, "extra": "ignore"}


class EnterpriseOnboardingResponse(BaseModel):
    """开通受理响应：只回状态/受理号/关联标识，不回任何提交资料。"""

    status: str
    accepted_no: str
    request_id: str


# ---------------------------------------------------------------------------
# 敏感声明（与上面的模型一一对应；新增字段必须在此同步登记）
# ---------------------------------------------------------------------------
_ID_DOCUMENT_NODE = group({
    # 证件号：法定证件标识，高敏感。
    "doc_number|cert_no": leaf(CAT_ID_NUMBER),
    # image_id 为内部影像句柄（业务标识），按内部数据处理。
    "image_id": leaf(CAT_BUSINESS),
    # doc_type 为有限枚举，显式非敏感（值保留，便于前端提示）。
    "doc_type": plain(),
})

_CONTACT_NODE = group({
    # 个人姓名。
    "name|contact_name": leaf(CAT_NAME),
    # 手机号（语义别名 phone/phoneNumber 由登记覆盖）。
    "mobile|phone|phoneNumber": leaf(CAT_CONTACT),
    # 邮箱（可选分支，出现即掩码；未出现不产生任何事件）。
    "email|mail|emailAddress": leaf(CAT_CONTACT),
    # 联系人下的多个证件，数组穿透。
    "id_documents": many(_ID_DOCUMENT_NODE),
    # role 为有限枚举，显式非敏感。
    "role|contact_role": plain(),
})

_ATTACHMENT_NODE = group({
    # 文件名：显式非敏感，区别于联系人的 name（路径决定级别）。
    "name|file_name": plain(),
    # 影像句柄：业务标识，按内部数据处理。
    "file_id|oss_key": leaf(CAT_BUSINESS),
})

_BANK_ACCOUNT_NODE = group({
    "account_name": plain(),  # 账户名（多为企业名），显式保留
    "bank_name": plain(),     # 开户行名称，显式保留
    "account_number|bank_card": leaf(CAT_FINANCE),  # 银行账号，掩码
})

_ONBOARDING_ROOT = group({
    "profile_version": plain(),
    "enterprise_name|corp_name": leaf(CAT_NAME),
    "unified_social_credit_code|credit_code": leaf(CAT_BUSINESS),
    "industry|industry_type": plain(),
    "contacts": many(_CONTACT_NODE),
    "attachments": many(_ATTACHMENT_NODE),
    "bank_account": _BANK_ACCOUNT_NODE,
    # remark 为自由备注，显式确认非敏感（内容保留，便于排查）。
    "remark": plain(),
})

#: 企业开通资料的敏感策略：路由、异常处理器、下游记录、日志共用。
ONBOARDING_POLICY: SensitivePolicy = build_policy(PROFILE_NAME, _ONBOARDING_ROOT)

__all__ = [
    "PROFILE_NAME",
    "IdDocument",
    "Contact",
    "Attachment",
    "BankAccount",
    "EnterpriseOnboardingRequest",
    "EnterpriseOnboardingResponse",
    "ONBOARDING_POLICY",
]
