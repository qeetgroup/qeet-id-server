// Package emailtmpl renders branded, responsive, email-client-safe HTML for
// transactional mail (verification codes, password resets, magic links). The
// layout is a single fluid card built with tables + inline styles (the lowest
// common denominator email clients render reliably), plus a <style> media query
// that enhances small screens where supported. Callers still pass a plain-text
// Body as the fallback.
package emailtmpl

import "html"

// Qeet brand tokens (mirrors @qeetrix/ui: brand orange, dark ink on brand).
const (
	brandName  = "Qeet ID"
	brandColor = "#ff6900"
	ink        = "#0a0a0a"
	textColor  = "#3f3f46"
	muted      = "#6b7280"
)

// qeetLogo is the Qeet "Q" brandmark inlined as SVG (the on-light variant, for
// the light email background). NOTE: Apple Mail renders inline SVG, but Gmail,
// Outlook and Yahoo strip it — in those clients the logo simply won't appear.
// A hosted PNG is the reliable option; inline SVG is used here by request.
const qeetLogo = `<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 1254 1254" style="display:block;margin:0 auto" role="img" aria-label="Qeet ID">
<defs><mask id="qBowlHole" maskUnits="userSpaceOnUse"><rect width="1254" height="1254" fill="#FFFFFF"/><path fill="#000000" d="M669.964722,338.242981 C714.535645,351.395386 751.471863,375.501129 779.470825,412.042328 C814.503479,457.763184 828.529907,509.627594 821.508301,567.354248 C815.037964,614.333862 796.163635,655.232849 763.035339,688.671509 C715.514587,736.637695 657.793396,758.218994 590.453552,749.188904 C504.824402,737.706116 436.176788,675.264038 417.429352,590.163330 C398.281219,503.243683 423.564056,429.604553 493.036591,373.787628 C542.333557,334.180542 599.844727,323.023224 661.836060,336.080780 C664.430725,336.627319 666.966248,337.454285 669.964722,338.242981 z"/></mask></defs>
<path mask="url(#qBowlHole)" fill="#0A0A0A" d="M821.791687,894.018799 C803.326172,903.166809 785.336975,913.478882 766.312927,921.261658 C682.977112,955.354797 597.577454,960.575989 510.776794,936.458923 C427.137451,913.220154 358.319214,867.022827 303.655487,799.771240 C259.619385,745.594543 231.852402,683.929749 219.855377,615.135681 C205.246201,531.363037 215.390701,450.569489 250.641022,373.361603 C287.752838,292.076569 346.057434,229.640503 423.650269,185.486679 C489.535767,147.994873 560.685242,131.387634 636.355042,134.347610 C667.607117,135.570114 698.193970,141.258041 728.247498,149.842102 C729.508179,150.202209 730.704346,150.788620 731.848389,151.967499 C730.448730,152.746170 729.071960,153.118286 727.822754,152.863968 C709.200012,149.072678 691.179749,151.872894 674.192566,159.455490 C609.452271,188.353607 598.711670,273.967438 647.019897,320.610840 C654.005493,327.355682 662.567566,332.467743 669.964722,338.242981 C666.966248,337.454285 664.430725,336.627319 661.836060,336.080780 C599.844727,323.023224 542.333557,334.180542 493.036591,373.787628 C423.564056,429.604553 398.281219,503.243683 417.429352,590.163330 C436.176788,675.264038 504.824402,737.706116 590.453552,749.188904 C657.793396,758.218994 715.514587,736.637695 763.035339,688.671509 C796.163635,655.232849 815.037964,614.333862 821.583984,568.151245 C821.813477,570.053894 822.135437,571.531555 822.135864,573.009338 C822.152954,633.669861 822.122437,694.330322 822.139038,754.990845 C822.151672,800.985046 822.219727,846.979187 822.106567,893.217285 C821.897339,893.647034 821.844543,893.832886 821.791687,894.018799 z"/>
<path fill="#F26D0E" d="M822.263123,892.973389 C822.219727,846.979187 822.151672,800.985046 822.139038,754.990845 C822.122437,694.330322 822.152954,633.669861 822.135864,573.009338 C822.135437,571.531555 821.813477,570.053894 821.565674,567.779114 C828.529907,509.627594 814.503479,457.763184 779.470825,412.042328 C751.471863,375.501129 714.535645,351.395386 670.400085,338.335388 C662.567566,332.467743 654.005493,327.355682 647.019897,320.610840 C598.711670,273.967438 609.452271,188.353607 674.192566,159.455490 C691.179749,151.872894 709.200012,149.072678 727.822754,152.863968 C729.071960,153.118286 730.448730,152.746170 731.992310,152.316010 C769.401550,160.954422 803.019836,177.923462 834.791809,198.657364 C880.962646,228.787796 919.463745,266.834351 950.460815,312.497620 C982.820740,360.168488 1003.902954,412.329163 1013.963745,469.046661 C1020.018982,503.183136 1020.544678,537.589294 1019.593262,572.806763 C1019.448914,575.015015 1019.590332,576.503357 1019.731812,577.991638 C1019.772949,580.350159 1019.814148,582.708679 1019.428955,585.628662 C1017.683411,593.105652 1016.613953,600.080200 1014.998474,606.925842 C1009.980408,628.190918 1005.808533,649.733887 999.348572,670.561157 C990.918884,697.739197 978.245422,723.197205 964.169678,747.999512 C946.413818,779.286499 923.983276,806.907410 899.392212,832.849548 C890.630920,842.092285 880.599915,850.155457 870.943115,858.519897 C855.853760,871.589722 839.671936,883.159241 822.263123,892.973389 z"/>
<path fill="#D85301" d="M822.106567,893.217285 C839.671936,883.159241 855.853760,871.589722 870.943115,858.519897 C880.599915,850.155457 890.630920,842.092285 899.392212,832.849548 C923.983276,806.907410 946.413818,779.286499 964.169678,747.999512 C978.245422,723.197205 990.918884,697.739197 999.348572,670.561157 C1005.808533,649.733887 1009.980408,628.190918 1014.998474,606.925842 C1016.613953,600.080200 1017.683411,593.105652 1019.364136,586.065613 C1019.808838,604.428406 1019.960144,622.915649 1019.964478,641.402893 C1019.996887,779.531555 1020.306824,917.661377 1019.819763,1055.788208 C1019.679565,1095.540405 1004.006104,1128.543701 969.487183,1150.236328 C923.479797,1179.148682 863.557739,1162.918457 837.012451,1115.253418 C826.966858,1097.215454 822.142151,1077.902100 822.083740,1057.398804 C821.929504,1003.248413 821.950806,949.097534 821.846924,894.482788 C821.844543,893.832886 821.897339,893.647034 822.106567,893.217285 z"/>
</svg>`

// logoPNGURL is a hosted PNG of the same mark, used as the fallback layer for
// clients that strip inline SVG (Gmail, Outlook, Yahoo). Set once at startup via
// SetLogoPNGURL; empty means SVG-only (renders in Apple Mail; wordmark elsewhere).
var logoPNGURL string

// SetLogoPNGURL configures the PNG fallback for the header logo. Call once
// during startup with a publicly-reachable PNG of the brand mark.
func SetLogoPNGURL(u string) { logoPNGURL = u }

// Code renders an email that presents a one-time code prominently.
func Code(heading, intro, code, expiry string) string {
	inner := heading1(heading) +
		paragraph(intro) +
		`<div style="text-align:center;margin:0 0 22px">` +
		`<span class="q-otp" style="display:inline-block;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;` +
		`font-size:30px;font-weight:700;letter-spacing:8px;color:` + ink + `;background:#fff7ed;` +
		`border:1px solid #fed7aa;border-radius:10px;padding:14px 8px 14px 16px">` +
		html.EscapeString(code) + `</span></div>` +
		note("This code expires in "+html.EscapeString(expiry)+
			". If you didn't request it, you can safely ignore this email.")
	return shell(inner)
}

// Action renders an email with a single primary button linking to url.
func Action(heading, intro, buttonLabel, url, extraNote string) string {
	safeURL := html.EscapeString(url)
	inner := heading1(heading) +
		paragraph(intro) +
		`<div style="text-align:center;margin:0 0 22px">` +
		`<a href="` + safeURL + `" class="q-btn" ` +
		`style="display:inline-block;background:` + brandColor + `;color:` + ink + `;font-size:15px;` +
		`font-weight:600;text-decoration:none;padding:13px 26px;border-radius:10px">` +
		html.EscapeString(buttonLabel) + `</a></div>` +
		`<p style="margin:0 0 6px;font-size:12px;line-height:18px;color:` + muted + `">` +
		`Or paste this link into your browser:</p>` +
		`<p style="margin:0 0 18px;font-size:12px;line-height:18px;word-break:break-all;color:` + brandColor + `">` +
		safeURL + `</p>` +
		note(html.EscapeString(extraNote))
	return shell(inner)
}

func heading1(s string) string {
	return `<h1 style="margin:0 0 10px;font-size:20px;line-height:26px;font-weight:700;color:` + ink + `">` +
		html.EscapeString(s) + `</h1>`
}

func paragraph(s string) string {
	return `<p style="margin:0 0 22px;font-size:15px;line-height:23px;color:` + textColor + `">` +
		html.EscapeString(s) + `</p>`
}

// note takes already-escaped (or safe) HTML.
func note(s string) string {
	return `<p style="margin:0;font-size:13px;line-height:20px;color:` + muted + `">` + s + `</p>`
}

// header is the centered logo lockup at the top of the card. It layers the
// inline SVG mark over a PNG background of the same mark: Apple Mail renders the
// crisp SVG on top; clients that strip inline SVG (Gmail, Outlook, Yahoo) but
// load images show the PNG underneath; the rest fall back to the wordmark below.
func header() string {
	mark := qeetLogo
	if logoPNGURL != "" {
		mark = `<div style="width:48px;height:48px;margin:0 auto;` +
			`background-image:url('` + html.EscapeString(logoPNGURL) + `');` +
			`background-repeat:no-repeat;background-position:center;background-size:48px 48px">` +
			qeetLogo + `</div>`
	}
	return `<div style="text-align:center;margin:0 0 22px">` +
		mark +
		`<div style="margin-top:10px;font-size:16px;font-weight:700;letter-spacing:0.2px;color:` + ink + `">` +
		brandName + `</div></div>`
}

// shell wraps card content in the branded, fluid outer frame. The card is
// width:100% with max-width:480px so it fills small screens and never forces
// horizontal scroll; the media query shrinks the code/button on narrow devices
// (clients that strip <style> still get the safe inline base).
func shell(inner string) string {
	return `<!doctype html><html lang="en"><head>` +
		`<meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<meta name="x-apple-disable-message-reformatting">` +
		`<style>` +
		`body{margin:0;padding:0;width:100%!important}` +
		`@media only screen and (max-width:600px){` +
		`.q-card{padding:22px 18px!important}` +
		`.q-otp{font-size:24px!important;letter-spacing:5px!important;padding:12px 6px 12px 11px!important}` +
		`.q-btn{display:block!important}` +
		`}` +
		`</style></head>` +
		`<body style="margin:0;padding:24px 12px;background:#f4f4f5;` +
		`font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" ` +
		`style="border-collapse:collapse;background:#f4f4f5">` +
		`<tr><td align="center" style="padding:0">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" ` +
		`style="width:100%;max-width:480px;border-collapse:collapse">` +
		`<tr><td class="q-card" style="background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;padding:32px">` +
		header() +
		inner +
		`</td></tr>` +
		`<tr><td style="padding:18px 4px 0;font-size:12px;line-height:18px;color:` + muted + `">` +
		`Sent by ` + brandName + `. If this wasn't you, no action is needed.` +
		`</td></tr>` +
		`</table></td></tr></table></body></html>`
}
