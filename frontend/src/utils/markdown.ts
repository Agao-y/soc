import DOMPurify from "dompurify";
import { marked } from "marked";

marked.setOptions({
  breaks: true,
  gfm: true,
});

export function renderMarkdown(text: string | null | undefined): string {
  if (!text) return "";
  const raw = marked.parse(text) as string;
  return DOMPurify.sanitize(raw, { ALLOWED_TAGS: ["p","br","strong","em","h1","h2","h3","ul","ol","li","code","pre","blockquote","hr","a"], ALLOWED_ATTR: ["href","target"] });
}

/** 为日志文本添加简单语法高亮 (IP / 端口 / 关键词) */
export function highlightLog(text: string | null | undefined): string {
  if (!text) return "";
  const escaped = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  return escaped
    // IP 地址高亮
    .replace(
      /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g,
      '<span class="hl-ip">$1</span>',
    )
    // 端口号高亮 (1-65535, 跟在 : 或 port 后面)
    .replace(
      /(?<![.\d])(\d{1,5})(?=\/tcp|\/udp|$)/gi,
      '<span class="hl-port">$1</span>',
    )
    // 关键词高亮
    .replace(
      /\b(failed|error|denied|blocked|attack|malware|injection|overflow|exploit|unauthorized|suspicious)\b/gi,
      '<span class="hl-keyword">$1</span>',
    )
    // 协议高亮
    .replace(
      /\b(TCP|UDP|HTTP|HTTPS|SSH|FTP|DNS|TLS|SSL|ICMP|RDP|SMTP)\b/g,
      '<span class="hl-proto">$1</span>',
    );
}
