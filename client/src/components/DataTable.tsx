import React, { useState, useMemo } from 'react';
import { Spinner } from './Spinner';
import { EmptyState } from './EmptyState';
import { Button } from './Button';
import { Alert } from './Alert';

/* eslint-disable @typescript-eslint/no-explicit-any */

export interface Column<T = Record<string, unknown>> {
  key: string;
  label: string;
  sortable?: boolean;
  width?: number | string;
  render?: (row: T) => React.ReactNode;
}

interface DataTableProps<T extends Record<string, any>> {
  columns: Column<T>[];
  data: T[];
  loading?: boolean;
  error?: string;
  onRetry?: () => void;
  onRowClick?: (row: T) => void;
  rowActions?: (row: T) => React.ReactNode;
  keyField?: string;
  searchKeys?: (keyof T)[];
  emptyTitle?: string;
  emptySubtitle?: string;
  emptyAction?: React.ReactNode;
  pageSize?: number;
}

const TH: React.CSSProperties = {
  height: 'var(--row-height)',
  padding: '0 12px',
  textAlign: 'left',
  fontSize: 'var(--font-size-xs)',
  fontWeight: 700,
  color: 'var(--color-text-muted)',
  background: 'var(--color-surface-2)',
  borderBottom: '1px solid var(--color-border)',
  position: 'sticky',
  top: 0,
  zIndex: 1,
  whiteSpace: 'nowrap',
  letterSpacing: '0.5px',
  textTransform: 'uppercase',
  userSelect: 'none',
};

const TD: React.CSSProperties = {
  height: 'var(--row-height)',
  padding: '0 12px',
  fontSize: 'var(--font-size-body)',
  borderBottom: '1px solid var(--color-border)',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
  maxWidth: 280,
  color: 'var(--color-text)',
};

function SkeletonRow({ cols }: { cols: number }) {
  return (
    <tr>
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} style={TD}>
          <div style={{
            height: 12,
            borderRadius: 3,
            background: 'var(--color-border)',
            width: `${50 + (i * 17) % 40}%`,
            animation: 'pulse 1.4s ease-in-out infinite',
          }} />
        </td>
      ))}
    </tr>
  );
}

export function DataTable<T extends Record<string, any>>({
  columns, data, loading, error, onRetry, onRowClick, rowActions,
  keyField = 'id', searchKeys, emptyTitle = 'No data', emptySubtitle,
  emptyAction, pageSize = 25,
}: DataTableProps<T>) {
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [page, setPage] = useState(1);

  const filtered = useMemo(() => {
    if (!search || !searchKeys) return data;
    const q = search.toLowerCase();
    return data.filter(row =>
      searchKeys.some(k => String(row[k as string] ?? '').toLowerCase().includes(q))
    );
  }, [data, search, searchKeys]);

  const sorted = useMemo(() => {
    if (!sortKey) return filtered;
    return [...filtered].sort((a, b) => {
      const av = String(a[sortKey] ?? '');
      const bv = String(b[sortKey] ?? '');
      return sortDir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
    });
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const paged = sorted.slice((page - 1) * pageSize, page * pageSize);

  const toggleSort = (key: string) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('asc'); }
    setPage(1);
  };

  const hasActions = !!rowActions;
  const colCount = columns.length + (hasActions ? 1 : 0);

  return (
    <div>
      {/* Search bar */}
      {searchKeys && (
        <div style={{ marginBottom: 'var(--sp-3)' }}>
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1); }}
            placeholder="Search…"
            style={{
              height: 'var(--input-height)',
              padding: '0 10px',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius)',
              fontSize: 'var(--font-size-body)',
              background: 'var(--color-surface)',
              color: 'var(--color-text)',
              width: 260,
              outline: 'none',
            }}
          />
        </div>
      )}

      {/* Error state */}
      {error && (
        <Alert kind="error">
          {error}
          {onRetry && (
            <Button variant="ghost" size="sm" onClick={onRetry} style={{ marginLeft: 8, color: 'var(--color-error)' }}>
              Retry
            </Button>
          )}
        </Alert>
      )}

      {/* Table */}
      <div style={{ border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', minWidth: 480 }}>
            <thead>
              <tr>
                {columns.map(col => (
                  <th
                    key={col.key}
                    style={{ ...TH, width: col.width, cursor: col.sortable ? 'pointer' : 'default' }}
                    onClick={() => col.sortable && toggleSort(col.key)}
                  >
                    {col.label}
                    {col.sortable && sortKey === col.key && (
                      <span style={{ marginLeft: 4, opacity: 0.7 }}>{sortDir === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </th>
                ))}
                {hasActions && <th style={{ ...TH, width: 80 }} />}
              </tr>
            </thead>
            <tbody>
              {loading
                ? Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cols={colCount} />)
                : !error && paged.length === 0
                  ? (
                    <tr>
                      <td colSpan={colCount}>
                        <EmptyState title={emptyTitle} subtitle={emptySubtitle} action={emptyAction} />
                      </td>
                    </tr>
                  )
                  : paged.map(row => (
                    <tr
                      key={String(row[keyField])}
                      onClick={() => onRowClick?.(row)}
                      style={{ cursor: onRowClick ? 'pointer' : 'default' }}
                      onMouseEnter={e => { (e.currentTarget as HTMLTableRowElement).style.background = 'var(--color-surface-2)'; }}
                      onMouseLeave={e => { (e.currentTarget as HTMLTableRowElement).style.background = ''; }}
                    >
                      {columns.map(col => (
                        <td key={col.key} style={TD} title={col.render ? undefined : String(row[col.key] ?? '')}>
                          {col.render ? col.render(row) : String(row[col.key] ?? '')}
                        </td>
                      ))}
                      {hasActions && (
                        <td style={{ ...TD, overflow: 'visible', textAlign: 'right', maxWidth: 'none' }} onClick={e => e.stopPropagation()}>
                          {rowActions!(row)}
                        </td>
                      )}
                    </tr>
                  ))
              }
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {!loading && !error && totalPages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 'var(--sp-3)', justifyContent: 'space-between', fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)' }}>
          <span>{sorted.length} total rows</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Button variant="secondary" size="sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>←</Button>
            <span>Page {page} of {totalPages}</span>
            <Button variant="secondary" size="sm" disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>→</Button>
          </div>
        </div>
      )}
    </div>
  );
}
