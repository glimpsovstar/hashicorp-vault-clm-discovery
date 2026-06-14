import type { ReactNode } from "react";

type PageHeaderProps = {
  title: string;
  subtitle?: string;
  description?: string;
  actions?: ReactNode;
  breadcrumbs?: ReactNode;
};

export default function PageHeader({
  title,
  subtitle,
  description,
  actions,
  breadcrumbs,
}: PageHeaderProps) {
  return (
    <header className="page-header">
      {breadcrumbs && <div className="page-header-breadcrumbs">{breadcrumbs}</div>}
      <div className="page-header-row">
        <div className="page-header-copy">
          {subtitle && <p className="page-header-subtitle">{subtitle}</p>}
          <h1 className="page-header-title">{title}</h1>
          {description && <p className="page-header-description">{description}</p>}
        </div>
        {actions && <div className="page-header-actions">{actions}</div>}
      </div>
    </header>
  );
}
