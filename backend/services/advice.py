ADVICE_MAP = {
    "恶意链接": "禁用邮件内直达链接；启用域名信誉校验与阻断；使用隔离浏览器或安全沙箱；核验发件域 SPF/DKIM/DMARC 并限制可疑 TLD。",
    "危险附件": "阻断可执行与启用宏的文档类型；启用沙箱扫描与内容解码；默认禁用宏；限制来自外部来源的附件执行权限。",
    "社会工程诱导": "加强安全意识培训与二次验证；收敛敏感信息传递渠道；为账户强制开启 MFA；在流程中加入来源核验与审批环节。",
    "生成文本伪装": "建立内容审批与异常风格审计；对模板化表述进行规则校验；结合来源可信度与上下文一致性进行复核。",
}

def get_advice(name: str) -> str:
    return ADVICE_MAP.get(name, "请进行来源核验与最小权限加固，并审计相关活动。")

def list_advices():
    return [{"name": k, "recommendation": v} for k, v in ADVICE_MAP.items()]
