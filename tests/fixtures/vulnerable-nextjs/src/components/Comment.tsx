// ❌ VULNERÁVEL — Componente com XSS
import React from "react";

interface CommentProps {
  body: string;
  author: string;
}

export function Comment({ body, author }: CommentProps) {
  // 🔴 SENT-XSS: dangerouslySetInnerHTML com dados do usuário
  return (
    <div>
      <h3>{author}</h3>
      <div dangerouslySetInnerHTML={{ __html: body }} />
    </div>
  );
}

export function RawContent({ html }: { html: string }) {
  // 🔴 SENT-XSS: innerHTML direto
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (ref.current) {
      ref.current.innerHTML = html;
    }
  }, [html]);

  return <div ref={ref} />;
}

export function LegacyRender({ content }: { content: string }) {
  // 🔴 SENT-XSS: document.write
  React.useEffect(() => {
    document.write(content);
  }, [content]);

  return null;
}
