import React, { useEffect, useState, useCallback } from 'react';
import { getAttendance, updateAttendance, commentAttendance } from '../../api/client';
import { DataTable, Column } from '../../components/DataTable';
import { PageHeader } from '../../components/PageHeader';
import { Badge, statusVariant } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Drawer } from '../../components/Drawer';
import { FormField, SelectInput, TextareaInput, TextInput } from '../../components/FormField';
import { Alert } from '../../components/Alert';
import { useToast } from '../../hooks/useToast';
import { ToastList } from '../../components/Toast';

/* eslint-disable @typescript-eslint/no-explicit-any */

const STATUSES = ['Present', 'Absent', 'Half Day', 'Leave', 'Holiday', 'Work From Home'];

export const AttendancePage: React.FC = () => {
  const { toasts, addToast, removeToast } = useToast();
  const [records, setRecords] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Detail drawer
  const [selected, setSelected] = useState<any | null>(null);
  const [editStatus, setEditStatus] = useState('');
  const [checkIn, setCheckIn] = useState('');
  const [checkOut, setCheckOut] = useState('');
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [commenting, setCommenting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const res = await getAttendance();
    setLoading(false);
    if (!res.ok) { setError(res.message); return; }
    setRecords(res.data?.records ?? []);
  }, []);

  useEffect(() => { load(); }, [load]);

  const openRecord = (rec: any) => {
    setSelected(rec);
    setEditStatus(rec.status);
    setCheckIn(rec.checkInTime ?? '');
    setCheckOut(rec.checkOutTime ?? '');
    setComment('');
  };

  const handleSave = async () => {
    if (!selected) return;
    setSaving(true);
    const res = await updateAttendance(selected.id, {
      status: editStatus,
      checkInTime: checkIn || undefined,
      checkOutTime: checkOut || undefined,
    });
    setSaving(false);
    if (!res.ok) { addToast('error', res.message); return; }
    addToast('success', 'Attendance updated');
    setSelected(null);
    load();
  };

  const handleComment = async () => {
    if (!selected || !comment.trim()) return;
    setCommenting(true);
    const res = await commentAttendance(selected.id, comment.trim());
    setCommenting(false);
    if (!res.ok) { addToast('error', res.message); return; }
    addToast('success', 'Comment added');
    setComment('');
    // Reload to get fresh comments
    const freshRes = await getAttendance();
    if (freshRes.ok) {
      const freshRecord = (freshRes.data?.records ?? []).find((r: any) => r.id === selected.id);
      if (freshRecord) setSelected(freshRecord);
    }
  };

  const columns: Column<any>[] = [
    { key: 'memberName', label: 'Member', sortable: true, width: 160 },
    { key: 'department', label: 'Department', sortable: true, width: 120 },
    { key: 'date', label: 'Date', sortable: true, width: 120, render: row =>
        row.date ? new Date(row.date).toLocaleDateString() : '—'
    },
    { key: 'status', label: 'Status', width: 130, render: row => <Badge variant={statusVariant(row.status)}>{row.status}</Badge> },
    { key: 'checkInTime', label: 'Check In', width: 90 },
    { key: 'checkOutTime', label: 'Check Out', width: 90 },
    { key: 'remarks', label: 'Remarks', width: 160 },
  ];

  return (
    <div className="page-body">
      <ToastList toasts={toasts} onRemove={removeToast} />
      <PageHeader
        title="Attendance"
        subtitle="View and manage team attendance records"
      />

      <DataTable
        columns={columns}
        data={records}
        loading={loading}
        error={error ?? undefined}
        onRetry={load}
        searchKeys={['memberName', 'department', 'status']}
        emptyTitle="No attendance records"
        emptySubtitle="Records will appear here once generated"
        onRowClick={openRecord}
      />

      {/* Detail / edit drawer */}
      <Drawer
        open={!!selected}
        title={`Attendance — ${selected?.memberName ?? ''}`}
        onClose={() => setSelected(null)}
        onSave={handleSave}
        saving={saving}
        saveLabel="Save Changes"
        width={520}
      >
        {selected && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-2)', marginBottom: 'var(--sp-4)', padding: '10px 12px', background: 'var(--color-surface-2)', borderRadius: 'var(--radius)', fontSize: 'var(--font-size-sm)' }}>
              <div><span style={{ color: 'var(--color-text-muted)' }}>Date:</span> <strong>{new Date(selected.date).toLocaleDateString()}</strong></div>
              <div><span style={{ color: 'var(--color-text-muted)' }}>Department:</span> <strong>{selected.department}</strong></div>
            </div>

            <FormField label="Status">
              <SelectInput value={editStatus} onChange={e => setEditStatus(e.target.value)}>
                {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
              </SelectInput>
            </FormField>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-4)' }}>
              <FormField label="Check In Time">
                <TextInput type="time" value={checkIn} onChange={e => setCheckIn(e.target.value)} />
              </FormField>
              <FormField label="Check Out Time">
                <TextInput type="time" value={checkOut} onChange={e => setCheckOut(e.target.value)} />
              </FormField>
            </div>

            {/* HR Comments */}
            <div style={{ borderTop: '1px solid var(--color-border)', paddingTop: 'var(--sp-4)', marginTop: 'var(--sp-2)' }}>
              <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--color-text-subtle)', marginBottom: 'var(--sp-3)' }}>
                HR Comments
              </div>
              {(selected.hrComments ?? []).length === 0 ? (
                <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)', marginBottom: 'var(--sp-3)' }}>No comments yet</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 'var(--sp-3)' }}>
                  {(selected.hrComments ?? []).map((c: any) => (
                    <div key={c.id} style={{ background: 'var(--color-surface-2)', borderRadius: 'var(--radius)', padding: '8px 10px', fontSize: 'var(--font-size-sm)' }}>
                      <div style={{ fontWeight: 600, color: 'var(--color-text)', marginBottom: 2 }}>{c.author}</div>
                      <div style={{ color: 'var(--color-text-muted)', lineHeight: 1.5 }}>{c.text}</div>
                      <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-subtle)', marginTop: 4 }}>{new Date(c.timestamp).toLocaleString()}</div>
                    </div>
                  ))}
                </div>
              )}
              <FormField label="Add Comment">
                <TextareaInput
                  placeholder="Write a note for this attendance record…"
                  value={comment}
                  onChange={e => setComment(e.target.value)}
                  style={{ minHeight: 56 }}
                />
              </FormField>
              <Button
                variant="secondary"
                onClick={handleComment}
                loading={commenting}
                disabled={!comment.trim()}
              >
                Add Comment
              </Button>
            </div>
          </>
        )}
      </Drawer>
    </div>
  );
};

