import { Controller, Get, Inject, Param, Req, Res } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { marked } from 'marked';
import { APP_CONFIG, type AppConfig } from '../config';
import { Public } from '../auth/principal';
import { Errors } from '../common/errors';

/** The only documents served, in navigation order (no directory browsing, no arbitrary paths). */
const PAGES = [
  { slug: 'quickstart', file: 'QUICKSTART.md', title: 'Quickstart' },
  { slug: 'integration-guide', file: 'INTEGRATION_GUIDE.md', title: 'Integration Guide' },
  { slug: 'evaluation', file: 'EVALUATION_PROTOCOL.md', title: 'Evaluation protocol' },
] as const;

/** Downloadable artifacts: SDK tarball, Python wheel/sdist. Exact-name match against this pattern. */
const DOWNLOAD_PATTERN = /^agenttrust(-sdk)?-\d+\.\d+\.\d+(\.tgz|\.tar\.gz|-py3-none-any\.whl)$/;

/**
 * Public developer portal for the hosted sandbox: Quickstart, Integration
 * Guide, API reference (OpenAPI rendered client-side) and SDK downloads.
 * Disabled unless AGENTTRUST_PUBLIC_DOCS=true. Read-only, static content;
 * `$BASE_URL` in the docs is replaced with this deployment's public URL.
 */
@Controller()
@SkipThrottle()
export class DocsController {
  constructor(@Inject(APP_CONFIG) private readonly config: AppConfig) {}

  private assertEnabled() {
    if (!this.config.publicDocs.enabled) throw Errors.notFound('Endpoint');
  }

  private baseUrl(req: Request): string {
    if (this.config.publicDocs.publicUrl) return this.config.publicDocs.publicUrl;
    // Derived from the request only as a fallback; a forged Host header must not inject markup.
    const host = req.get('host') ?? '';
    return `${req.protocol === 'https' ? 'https' : 'http'}://${/^[A-Za-z0-9.-]{1,253}(:\d{1,5})?$/.test(host) ? host : 'localhost'}`;
  }

  @Get()
  @Public()
  root(@Res() res: Response) {
    this.assertEnabled();
    res.redirect(302, '/docs');
  }

  private downloads(): string[] {
    const dir = this.config.publicDocs.downloadsDir;
    if (!existsSync(dir)) return [];
    return readdirSync(dir).filter((f) => DOWNLOAD_PATTERN.test(f) && statSync(path.join(dir, f)).isFile()).sort();
  }

  @Get('docs')
  @Public()
  index(@Req() req: Request, @Res() res: Response) {
    this.assertEnabled();
    const base = this.baseUrl(req);
    const files = this.downloads();
    const body = `
      <h1>AgentTrust developer sandbox</h1>
      <p class="lede">AgentTrust checks that an AI agent's payment matches what the business actually approved before it can execute.
      This sandbox moves <strong>no real money</strong> and is not production-ready, certified or audited.</p>
      <h2>Start here</h2>
      <ol>${PAGES.map((p) => `<li><a href="/docs/${p.slug}">${p.title}</a></li>`).join('')}<li><a href="/docs/reference">API reference</a> (<a href="/docs/openapi.yaml">openapi.yaml</a>)</li></ol>
      <h2>SDKs</h2>
      ${files.length ? `<ul>${files.map((f) => `<li><a href="/downloads/${f}">${f}</a><br><code>${f.endsWith('.tgz') ? 'npm install' : 'pip install'} ${base}/downloads/${f}</code></li>`).join('')}</ul>` : '<p>No SDK artifacts are published on this deployment.</p>'}
      <h2>Base URL</h2><p><code>${escapeHtml(base)}</code></p>`;
    res.type('html').send(layout('AgentTrust sandbox', body));
  }

  @Get('docs/reference')
  @Public()
  reference(@Res() res: Response) {
    this.assertEnabled();
    // Scalar renders the OpenAPI document client-side. Sandbox docs only.
    res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>AgentTrust API reference</title>
      <meta name="viewport" content="width=device-width, initial-scale=1"></head><body>
      <script id="api-reference" data-url="/docs/openapi.yaml"></script>
      <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference@1"></script></body></html>`);
  }

  @Get('docs/openapi.yaml')
  @Public()
  openapi(@Req() req: Request, @Res() res: Response) {
    this.assertEnabled();
    const spec = readFileSync(path.join(this.config.publicDocs.docsDir, 'openapi.yaml'), 'utf8').replace(
      /servers:\n(?:  - .*\n(?:    .*\n)*)+/,
      `servers:\n  - url: ${this.baseUrl(req)}\n    description: This sandbox\n`,
    );
    res.type('application/yaml').send(spec);
  }

  @Get('docs/:slug')
  @Public()
  page(@Req() req: Request, @Res() res: Response, @Param('slug') slug: string) {
    this.assertEnabled();
    const page = PAGES.find((p) => p.slug === slug);
    if (!page) throw Errors.notFound('Page');
    const md = readFileSync(path.join(this.config.publicDocs.docsDir, page.file), 'utf8')
      .replaceAll('$BASE_URL', this.baseUrl(req))
      // Cross-links between docs → portal routes.
      .replace(/\]\((?:\.\/)?QUICKSTART\.md/g, '](/docs/quickstart')
      .replace(/\]\((?:\.\/)?INTEGRATION_GUIDE\.md/g, '](/docs/integration-guide')
      .replace(/\]\((?:\.\/)?EVALUATION_PROTOCOL\.md/g, '](/docs/evaluation')
      .replace(/\]\((?:\.\/)?openapi\.yaml\)/g, '](/docs/reference)')
      // GitHub-style alerts → plain blockquote labels.
      .replace(/^> \[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$/gm, (_m, k: string) => `> **${k.charAt(0)}${k.slice(1).toLowerCase()}:**`);
    const html = marked.parse(md, { async: false }) as string;
    res.type('html').send(layout(`${page.title} · AgentTrust`, `<p><a href="/docs">← Developer sandbox</a></p>${html}`));
  }

  @Get('downloads/:file')
  @Public()
  download(@Res() res: Response, @Param('file') file: string) {
    this.assertEnabled();
    if (!DOWNLOAD_PATTERN.test(file) || !this.downloads().includes(file)) throw Errors.notFound('File');
    res.download(path.join(this.config.publicDocs.downloadsDir, file), file);
  }
}

function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

function layout(title: string, body: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  body{font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:860px;margin:0 auto;padding:24px;color:#1f2328}
  .banner{background:#fff8c5;border:1px solid #d4a72c;border-radius:6px;padding:8px 12px;margin-bottom:24px;font-size:14px}
  pre{background:#f6f8fa;padding:12px;border-radius:6px;overflow:auto}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
  table{border-collapse:collapse}td,th{border:1px solid #d0d7de;padding:6px 10px;vertical-align:top}blockquote{border-left:4px solid #d0d7de;margin:0;padding:0 12px;color:#57606a}
  a{color:#0969da}.lede{font-size:18px}
</style></head><body>
<div class="banner">Sandbox: no real money moves. Not production-ready, certified or audited.</div>
${body}
<script type="module">
  import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
  document.querySelectorAll('code.language-mermaid').forEach((el) => { const d = document.createElement('div'); d.className = 'mermaid'; d.textContent = el.textContent; el.parentElement.replaceWith(d); });
  mermaid.initialize({ startOnLoad: true });
</script>
</body></html>`;
}
