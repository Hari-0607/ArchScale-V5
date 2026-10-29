import React, { useEffect, useState } from 'react';
import { addAttendanceCommentApi, getAttendanceApi, updateAttendanceApi } from '../api/client';
import { DataTable, Column } from '../components/DataTable';
import { Drawer } from '../components/Drawer';
import { StatusBadge } from '../components/StatusBadge';
import { AttendanceItem } from '../types';

export const AttendanceApp: React.FC = () => {
  const [records, setRecords] = useState<AttendanceItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Comments Drawer
  const [activeRecord, setActiveRecord] = useState<AttendanceItem | null>(null);
  const [commentText, setCommentText] = useState('');
  const [commentLoading, setCommentLoading] = useState(false);

  const loadAttendance = async () => {
    setLoading(true);
    setError(null);
    const res = await getAttendanceApi();
    setLoading(false);

    if (!res.ok) {
      setError(
        res.error ||
          '403 Forbidden: Restricted Attendance Policy. By default, Tenant Admins, Design Managers, and other non-HR members are strictly prohibited from viewing Attendance.'
      );
    } else {
      setRecords(res.records || []);
    }
  };

  useEffect(() => {
    loadAttendance();
  }, []);

  const handleStatusUpdate = async (id: string, newStatus: string) => {
    const res = await updateAttendanceApi(id, { status: newStatus });
    if (res.ok) {
      loadAttendance();
    } else {
      alert('Edit Denied: ' + (res.error || 'Only HR Manager may edit attendance values. Junior HR is restricted to commenting.'));
    }
  };

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeRecord || !commentText.trim()) return;

    setCommentLoading(true);
    const res = await addAttendanceCommentApi(activeRecord.id, commentText.trim());
    setCommentLoading(false);

    if (res.ok) {
      setCommentText('');
      setActiveRecord(null);
      loadAttendance();
    } else {
      alert('Comment rejected: ' + (res.error || 'Permission denied'));
    }
  };

  const columns: Column<AttendanceItem>[] = [
    {
      header: 'Member Name',
      accessor: 'memberName',
      render: (r) => (
        <div>
          <strong style={{ color: '#f8fafc' }}>{r.memberName}</strong>
          <div style={{ fontFamily: 'monospace', fontSize: '11px', color: '#94a3b8' }}>{r.attendanceId}</div>
        </div>
      ),
    },
    {
      header: 'Department',
      accessor: 'department',
      render: (r) => <span>{r.department}</span>,
    },
    {
      header: 'Date',
      accessor: 'date',
      render: (r) => <span>{r.date}</span>,
    },
    {
      header: 'Times (In / Out)',
      render: (r) => (
        <span style={{ fontSize: '12px', color: '#cbd5e1' }}>
          {r.checkInTime || '09:00 AM'} — {r.checkOutTime || '06:00 PM'}
        </span>
      ),
    },
    {
      header: 'Attendance Status',
      accessor: 'status',
      render: (r) => (
        <select
          value={r.status}
          onChange={(e) => handleStatusUpdate(r.id, e.target.value)}
          style={{
            background: '#0d1322',
            border: '1px solid #334155',
            color: '#f8fafc',
            padding: '4px 8px',
            borderRadius: '4px',
            fontSize: '12px',
          }}
        >
          <option value="Present">Present</option>
          <option value="Absent">Absent</option>
          <option value="Half Day">Half Day</option>
          <option value="Leave">Leave</option>
          <option value="Holiday">Holiday</option>
          <option value="Work From Home">Work From Home</option>
        </select>
      ),
    },
    {
      header: 'HR Comments & Remarks',
      render: (r) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '12px', color: '#94a3b8' }}>
            {r.hrComments?.length ? `${r.hrComments.length} comment(s)` : r.remarks || 'No remarks'}
          </span>
          <button
            onClick={() => setActiveRecord(r)}
            style={{
              background: '#1e293b',
              color: '#38bdf8',
              border: '1px solid #334155',
              padding: '2px 8px',
              borderRadius: '4px',
              fontSize: '11px',
              cursor: 'pointer',
            }}
          >
            💬 Comments
          </button>
        </div>
      ),
    },
  ];

  return (
    <div style={{ background: '#111827', border: '1px solid #2d3748', borderRadius: '10px', padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#f8fafc', margin: '0 0 4px 0' }}>
            ⏱️ Test Application B — Attendance (Restricted Access)
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '13px', margin: 0 }}>
            Strict permission matrix: HR Manager (view/edit), Junior HR (view/comment only), Tenant Admin & other members (denied by default).
          </p>
        </div>

        <button
          onClick={loadAttendance}
          style={{
            background: '#2563eb',
            color: 'white',
            border: 'none',
            padding: '6px 14px',
            borderRadius: '6px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          🔄 Refresh Attendance
        </button>
      </div>

      {error ? (
        <div
          style={{
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            color: '#fca5a5',
            padding: '18px',
            borderRadius: '8px',
            fontSize: '13px',
            lineHeight: 1.5,
          }}
        >
          <strong style={{ fontSize: '15px' }}>🔒 Restricted Access Barrier (403 Forbidden)</strong>
          <p style={{ margin: '8px 0 0', color: '#fecaca' }}>{error}</p>
          <div style={{ marginTop: '12px', padding: '10px', background: 'rgba(0, 0, 0, 0.25)', borderRadius: '4px', fontSize: '12px' }}>
            <strong>Section 11 Matrix Rule:</strong> Tenant Admins, Design Managers, and other non-HR members cannot view Attendance, including their own records. Sign in as <strong>HR Manager</strong> (view/edit) or <strong>Junior HR</strong> (view/comment) to access this application.
          </div>
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={records}
          loading={loading}
          searchKey="memberName"
          searchPlaceholder="Search attendance records..."
        />
      )}

      {/* HR Comments Drawer */}
      <Drawer
        isOpen={activeRecord !== null}
        onClose={() => setActiveRecord(null)}
        title={`Attendance Comments: ${activeRecord?.memberName || ''}`}
        subtitle={`Date: ${activeRecord?.date || ''} | Department: ${activeRecord?.department || ''}`}
      >
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '16px' }}>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <h4 style={{ fontSize: '13px', color: '#94a3b8', textTransform: 'uppercase', marginBottom: '8px' }}>
              Comment History (Audited)
            </h4>

            {activeRecord?.hrComments && activeRecord.hrComments.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {activeRecord.hrComments.map((c) => (
                  <div
                    key={c.id}
                    style={{
                      background: '#161f30',
                      border: '1px solid #2d3748',
                      borderRadius: '6px',
                      padding: '12px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <strong style={{ fontSize: '12px', color: '#60a5fa' }}>{c.author}</strong>
                      <span style={{ fontSize: '11px', color: '#64748b' }}>
                        {new Date(c.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <p style={{ margin: 0, fontSize: '13px', color: '#f1f5f9' }}>{c.text}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ color: '#64748b', fontSize: '13px' }}>No comments recorded yet.</p>
            )}
          </div>

          <form onSubmit={handleAddComment} style={{ borderTop: '1px solid #2d3748', paddingTop: '16px' }}>
            <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
              Append New HR Comment
            </label>
            <textarea
              rows={3}
              placeholder="Enter verified HR comment..."
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
              style={{
                width: '100%',
                background: '#0d1322',
                border: '1px solid #2d3748',
                color: '#f8fafc',
                padding: '10px 12px',
                borderRadius: '6px',
                fontSize: '13px',
                boxSizing: 'border-box',
                marginBottom: '10px',
              }}
            />
            <button
              type="submit"
              disabled={commentLoading}
              style={{
                background: '#059669',
                color: 'white',
                border: 'none',
                padding: '8px 16px',
                borderRadius: '6px',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {commentLoading ? 'Saving...' : 'Add Comment'}
            </button>
          </form>
        </div>
      </Drawer>
    </div>
  );
};
