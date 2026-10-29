import React, { useEffect, useState } from 'react';
import { createTaskApi, getMembersApi, getTasksApi, reviewTaskApi, updateTaskStatusApi } from '../api/client';
import { DataTable, Column } from '../components/DataTable';
import { Drawer } from '../components/Drawer';
import { StatusBadge } from '../components/StatusBadge';
import { TaskItem, TeamMember } from '../types';

export const TasksApp: React.FC = () => {
  const [tasks, setTasks] = useState<TaskItem[]>([]);
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // New Task Drawer
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [assignedToId, setAssignedToId] = useState('');
  const [department, setDepartment] = useState('Design');
  const [priority, setPriority] = useState<TaskItem['priority']>('Normal');
  const [dueDate, setDueDate] = useState('');
  const [requiresApproval, setRequiresApproval] = useState(false);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    const [tasksRes, membersRes] = await Promise.all([getTasksApi(), getMembersApi()]);
    setLoading(false);

    if (!tasksRes.ok) {
      setError(tasksRes.error || 'Failed to load tasks');
    } else {
      setTasks(tasksRes.tasks || []);
    }

    if (membersRes.ok && membersRes.members) {
      setMembers(membersRes.members);
      if (membersRes.members.length > 0) {
        setAssignedToId(membersRes.members[0].id);
      }
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCreateTask = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title) return;

    const assignedMember = members.find((m) => m.id === assignedToId);
    const reviewer = assignedMember?.reportingManagerId
      ? members.find((m) => m.id === assignedMember.reportingManagerId)
      : undefined;

    const res = await createTaskApi({
      title,
      description,
      assignedToId,
      assignedToName: assignedMember?.name || 'Assigned Member',
      department,
      reviewerId: reviewer?.id || assignedToId,
      reviewerName: reviewer?.name || 'Manager',
      priority,
      dueDateTime: dueDate || new Date(Date.now() + 7 * 86400000).toISOString(),
      status: 'To Do',
      approvalStatus: requiresApproval ? 'Pending' : 'Not Required',
    });

    if (res.ok) {
      setIsDrawerOpen(false);
      setTitle('');
      setDescription('');
      loadData();
    } else {
      alert('Task creation failed: ' + res.error);
    }
  };

  const handleStatusChange = async (taskId: string, newStatus: string) => {
    const res = await updateTaskStatusApi(taskId, newStatus);
    if (res.ok) {
      loadData();
    } else {
      alert('Failed to update status: ' + res.error);
    }
  };

  const handleReview = async (taskId: string, approval: 'Approved' | 'Rejected') => {
    const res = await reviewTaskApi(taskId, approval);
    if (res.ok) {
      loadData();
    } else {
      alert('Review action failed: ' + (res.error || 'Permission denied'));
    }
  };

  const columns: Column<TaskItem>[] = [
    {
      header: 'Work ID / Title',
      render: (t) => (
        <div>
          <strong style={{ color: '#f8fafc' }}>{t.title}</strong>
          <div style={{ fontFamily: 'monospace', fontSize: '11px', color: '#94a3b8' }}>
            {t.workId || t.id?.substring(0, 8)}
          </div>
        </div>
      ),
    },
    {
      header: 'Department',
      accessor: 'department',
      render: (t) => <span>{t.department}</span>,
    },
    {
      header: 'Assigned To',
      accessor: 'assignedToName',
      render: (t) => <span>{t.assignedToName || 'Unassigned'}</span>,
    },
    {
      header: 'Priority',
      accessor: 'priority',
      render: (t) => <StatusBadge status={t.priority} />,
    },
    {
      header: 'Status',
      accessor: 'status',
      render: (t) => (
        <select
          value={t.status}
          onChange={(e) => handleStatusChange(t.id, e.target.value)}
          style={{
            background: '#0d1322',
            border: '1px solid #334155',
            color: '#f8fafc',
            padding: '4px 8px',
            borderRadius: '4px',
            fontSize: '12px',
          }}
        >
          <option value="To Do">To Do</option>
          <option value="In Progress">In Progress</option>
          <option value="In Review">In Review</option>
          <option value="Completed">Completed</option>
        </select>
      ),
    },
    {
      header: 'Approval',
      accessor: 'approvalStatus',
      render: (t) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <StatusBadge status={t.approvalStatus} />
          {t.approvalStatus === 'Pending' && (
            <div style={{ display: 'flex', gap: '4px' }}>
              <button
                onClick={() => handleReview(t.id, 'Approved')}
                title="Approve"
                style={{
                  background: '#059669',
                  color: 'white',
                  border: 'none',
                  padding: '2px 6px',
                  borderRadius: '3px',
                  fontSize: '11px',
                  cursor: 'pointer',
                }}
              >
                ✓
              </button>
              <button
                onClick={() => handleReview(t.id, 'Rejected')}
                title="Reject"
                style={{
                  background: '#dc2626',
                  color: 'white',
                  border: 'none',
                  padding: '2px 6px',
                  borderRadius: '3px',
                  fontSize: '11px',
                  cursor: 'pointer',
                }}
              >
                ✕
              </button>
            </div>
          )}
        </div>
      ),
    },
  ];

  return (
    <div style={{ background: '#111827', border: '1px solid #2d3748', borderRadius: '10px', padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#f8fafc', margin: '0 0 4px 0' }}>
            📋 Test Application A — Tasks
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '13px', margin: 0 }}>
            Verifies record-level ownership, reporting manager reviewers, and Design Manager cross-team read exceptions.
          </p>
        </div>

        <button
          onClick={() => setIsDrawerOpen(true)}
          style={{
            background: '#2563eb',
            color: 'white',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '6px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          + Create Task
        </button>
      </div>

      {error ? (
        <div
          style={{
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            color: '#fca5a5',
            padding: '14px',
            borderRadius: '6px',
            fontSize: '13px',
          }}
        >
          {error}
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={tasks}
          loading={loading}
          searchKey="title"
          searchPlaceholder="Search tasks..."
          emptyMessage="No tasks found matching your visibility scope."
        />
      )}

      {/* Create Task Drawer */}
      <Drawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        title="Create New Task"
        subtitle="Assign work to an 11-member team representative."
        footer={
          <>
            <button
              onClick={() => setIsDrawerOpen(false)}
              style={{
                background: '#334155',
                color: '#f8fafc',
                border: 'none',
                padding: '8px 14px',
                borderRadius: '6px',
                fontSize: '13px',
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              onClick={handleCreateTask}
              style={{
                background: '#2563eb',
                color: 'white',
                border: 'none',
                padding: '8px 16px',
                borderRadius: '6px',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Create Task
            </button>
          </>
        }
      >
        <form onSubmit={handleCreateTask}>
          <div style={{ marginBottom: '14px' }}>
            <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
              Task Title
            </label>
            <input
              type="text"
              placeholder="e.g. Schematic Blueprint Phase 1"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              style={{
                width: '100%',
                background: '#0d1322',
                border: '1px solid #2d3748',
                color: '#f8fafc',
                padding: '10px 12px',
                borderRadius: '6px',
                fontSize: '13px',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ marginBottom: '14px' }}>
            <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
              Description
            </label>
            <textarea
              rows={3}
              placeholder="Task details and scope..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              style={{
                width: '100%',
                background: '#0d1322',
                border: '1px solid #2d3748',
                color: '#f8fafc',
                padding: '10px 12px',
                borderRadius: '6px',
                fontSize: '13px',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '14px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
                Department
              </label>
              <select
                value={department}
                onChange={(e) => setDepartment(e.target.value)}
                style={{
                  width: '100%',
                  background: '#0d1322',
                  border: '1px solid #2d3748',
                  color: '#f8fafc',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  fontSize: '13px',
                }}
              >
                <option value="Design">Design</option>
                <option value="Accounts">Accounts</option>
                <option value="HR">HR</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
                Priority
              </label>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value as any)}
                style={{
                  width: '100%',
                  background: '#0d1322',
                  border: '1px solid #2d3748',
                  color: '#f8fafc',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  fontSize: '13px',
                }}
              >
                <option value="Low">Low</option>
                <option value="Normal">Normal</option>
                <option value="High">High</option>
                <option value="Urgent">Urgent</option>
              </select>
            </div>
          </div>

          <div style={{ marginBottom: '14px' }}>
            <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
              Assigned To (Member)
            </label>
            <select
              value={assignedToId}
              onChange={(e) => setAssignedToId(e.target.value)}
              style={{
                width: '100%',
                background: '#0d1322',
                border: '1px solid #2d3748',
                color: '#f8fafc',
                padding: '8px 12px',
                borderRadius: '6px',
                fontSize: '13px',
              }}
            >
              {members.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name || m.email} ({m.department} — {m.jobRole})
                </option>
              ))}
            </select>
          </div>

          <div style={{ marginBottom: '14px' }}>
            <label style={{ display: 'block', fontSize: '13px', color: '#cbd5e1', marginBottom: '6px', fontWeight: 600 }}>
              Due Date
            </label>
            <input
              type="date"
              value={dueDate}
              onChange={(e) => setDueDate(e.target.value)}
              style={{
                width: '100%',
                background: '#0d1322',
                border: '1px solid #2d3748',
                color: '#f8fafc',
                padding: '8px 12px',
                borderRadius: '6px',
                fontSize: '13px',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '16px' }}>
            <input
              type="checkbox"
              id="req-approval"
              checked={requiresApproval}
              onChange={(e) => setRequiresApproval(e.target.checked)}
              style={{ width: 'auto' }}
            />
            <label htmlFor="req-approval" style={{ fontSize: '13px', color: '#cbd5e1', cursor: 'pointer' }}>
              Requires Manager / Reviewer Approval
            </label>
          </div>
        </form>
      </Drawer>
    </div>
  );
};
