export function CardSkeleton() {
  return (
    <div className="skeleton-card">
      <div className="skeleton-avatar" />
      <div className="skeleton-content">
        <div className="skeleton-line skeleton-line-lg" />
        <div className="skeleton-line" />
      </div>
    </div>
  );
}

export function ListSkeleton({ count = 5 }: { count?: number }) {
  return (
    <>
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="skeleton-list-item">
          <div className="skeleton-icon" />
          <div className="skeleton-content">
            <div className="skeleton-line skeleton-line-md" />
            <div className="skeleton-line skeleton-line-sm" />
          </div>
        </div>
      ))}
    </>
  );
}

export function PageSkeleton() {
  return (
    <div className="skeleton-page">
      <div className="skeleton-header">
        <div className="skeleton-line skeleton-line-xl" />
      </div>
      <div className="skeleton-body">
        <ListSkeleton />
      </div>
    </div>
  );
}
