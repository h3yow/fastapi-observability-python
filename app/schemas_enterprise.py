"""企业实名开通场景的请求/响应模型与敏感字段声明。

两件事“同源”：

1. **输入识别**：顶层模型挂了一个 ``model_validator(mode="before")``，调用
   :func:`normalize_payload_for_model` 按字段元数据把键归一为规范字段名——
   大小写、下划线、连字符折叠后相等即同一字段（``certNumber`` /
   ``cert_number`` / ``cert-number`` / ``CERT_NUMBER``），嵌套对象、数组、
   可选分支统一处理。新增字段无需再逐条枚举别名写法；
2. **敏感范围**：通过 :func:`bind_model_policy` 与命名场景
   ``enterprise_onboarding`` 绑定，敏感类别按规范路径用 ``policy.mark(...)``
   声明。同一字段名在不同子结构中可以有不同级别（法人姓名敏感，
   联系人姓名非敏感）。新增资料版本只需扩展模型并补 mark，公共配置无需改动。

解析侧与脱敏侧共用同一个 :func:`normalize_key`，所以“能解析进来”与
“被判定为敏感”永远是同一套口径。
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator

from app.observability.sensitivity import (
    FieldCategory,
    SensitivityPolicy,
    bind_model_policy,
    normalize_payload_for_model,
    register_policy,
)


class ContactInfo(BaseModel):
    """联系人：姓名非敏感（可在错误提示中保留）；手机号/邮箱为联系方式敏感。"""

    name: str = Field(min_length=1, max_length=64)
    # 同义词：折叠大小写/下划线/连字符后仍不同形的写法（mobile），以及常见的
    # 合体写法（mobilePhone -> mobilephone）。其余变体由统一归一规则覆盖。
    phone: str = Field(
        min_length=5,
        max_length=32,
        json_schema_extra={"input_synonyms": ["mobile", "mobilephone"]},
    )
    email: str | None = Field(default=None, min_length=3, max_length=128)


class CertificateInfo(BaseModel):
    """证件：号码为证件敏感；证件类型/发证日期非敏感。"""

    cert_type: str = Field(default="ID_CARD", max_length=32)
    cert_number: str = Field(min_length=6, max_length=32)
    issued_date: str | None = Field(default=None, max_length=16)


class LegalRepresentative(BaseModel):
    """法人：姓名（实名信息）与证件号码/嵌套证件对象整体敏感。"""

    name: str = Field(min_length=1, max_length=64)
    # 顶层号码写法与嵌套证件对象二选一（可选分支）。
    id_number: str | None = Field(default=None, min_length=6, max_length=32)
    certificate: CertificateInfo | None = None


class BankAccount(BaseModel):
    """结算账户：开户名非敏感（用于提示），账号为金融敏感。"""

    account_name: str = Field(min_length=1, max_length=64)
    account_number: str = Field(min_length=8, max_length=40)
    bank_name: str | None = Field(default=None, max_length=64)


class Attachment(BaseModel):
    """附件描述：文件名非敏感；下载地址可能带签名 token，凭据敏感。"""

    filename: str = Field(min_length=1, max_length=128)
    file_type: str | None = Field(default=None, max_length=32)
    download_url: str | None = Field(default=None, max_length=512)


class EnterpriseOnboardingRequest(BaseModel):
    """企业实名开通请求：嵌套对象 + 数组 + 别名写法 + 可选分支。"""

    enterprise_name: str = Field(min_length=2, max_length=128)
    # 统一社会信用代码（企业标识，按非敏感企业资料处理，可在错误中回显）。
    credit_code: str = Field(min_length=8, max_length=32)
    legal_representative: LegalRepresentative
    # 联系人和附件都可能是多条；逐条按子结构判定，不漏任何一条。
    contacts: list[ContactInfo] = Field(default_factory=list, max_length=20)
    bank_account: BankAccount | None = None
    attachments: list[Attachment] = Field(default_factory=list, max_length=20)
    remark: str | None = Field(default=None, max_length=256)

    @model_validator(mode="before")
    @classmethod
    def _normalize_input(cls, data: Any) -> Any:
        """进入 pydantic 前按字段元数据归一键写法（大小写/下划线/连字符）。"""
        if isinstance(data, dict):
            return normalize_payload_for_model(data, cls)
        return data


class EnterpriseOnboardingResponse(BaseModel):
    status: str
    request_id: str
    enterprise_name: str


# ---------------------------------------------------------------------------
# 场景敏感声明（与模型同源；新增字段只改这里与模型，公共配置无需改动）
# ---------------------------------------------------------------------------

_POLICY: SensitivityPolicy = register_policy("enterprise_onboarding")

# 法人实名信息（姓名 + 顶层证件号 + 嵌套证件对象整体）。
_POLICY.mark(("legal_representative", "name"), FieldCategory.ID_DOCUMENT)
_POLICY.mark(("legal_representative", "id_number"), FieldCategory.ID_DOCUMENT)
_POLICY.mark(("legal_representative", "certificate"), FieldCategory.ID_DOCUMENT)

# 联系人：手机号/邮箱敏感；姓名不声明（与法人姓名形成同名不同级）。
_POLICY.mark(("contacts", "phone"), FieldCategory.CONTACT)
_POLICY.mark(("contacts", "email"), FieldCategory.CONTACT)

# 结算账户：账号金融敏感。
_POLICY.mark(("bank_account", "account_number"), FieldCategory.FINANCIAL)

# 附件下载地址（可能携带签名 token）：凭据敏感；文件名不声明。
_POLICY.mark(("attachments", "download_url"), FieldCategory.CREDENTIAL)

# 模型与策略绑定：元数据（字段层级/数组/可选分支）立即内省生效。
bind_model_policy(EnterpriseOnboardingRequest, _POLICY)
