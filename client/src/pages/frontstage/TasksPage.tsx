import React, { useEffect, useState, useCallback } from 'react';
import { getTasks, createTask, updateTask, approveTask, getMembers } from '../../api/client';
import { DataTable, Column } from '../../components/DataTable';
import { PageHeader } from '../../components/PageHeader';
import { Badge, statusVariant } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Drawer } from '../../components/Drawer';
import { FormField, TextInput, SelectInput, TextareaInput } from '../../components/FormField';
import { useToast } from '../../hooks/useToast';
import { ToastList } from '../../components/Toast';
import { useForm } from '../../hooks/useForm';
import { useSession } from '../../hooks/useSession';

/* eslint-disable @typescript-eslint/no-explicit-any */

const PRIORITIES = ['Low', 'Normal', 'High', 'Urgent'];
const STATUSES = ['To Do', 'In Progress', 'In Review', 'Completed'];

interface TaskForm {
  title: string;
  description: string;
  assignedToId: string;
  department: string;
  reviewerId: string;
  startDate: string;
  dueDateTime: string;
  priority: string;
}

const INITIAL: TaskForm = {
  title: '',
  description: '',
  assignedToId: '',
  department: 'Design',
  reviewerId: '',
  startDate: '',
  dueDateTime: '',
  priority: 'Normal',
};

export const TasksPage: React.FC = () => {
  const { session, context } = useSession();
  const { toasts, addToast, removeToast } = useToast();
  const [tasks, setTasks] = useState<any[]>([]);
  const [members, setMembers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [statusUpdating, setStatusUpdating] = useState<string | null>(null);

  // RBAC resolution
  const activeRole = context?.roleKey ?? session?.demoPersona?.role ?? session?.principal.role;
  const activeDept = context?.department ?? session?.demoPersona?.dept ?? session?.principal.department;
  const activeMemberId = context?.membershipId ?? session?.demoPersona?.memberId ?? session?.principal.id;

  const isJunior = activeRole === 'intern';
  const isManager = activeRole === 'leader' || activeRole === 'manager_coordinator';
  const isTenantAdmin = activeRole === 'business_owner' || activeRole === 'founder';
  const canCreateTask = isTenantAdmin || isManager;

  const { values, errors, set, validate, reset, submitting, setSubmitting, dirty } = useForm<TaskForm>(
    {
      ...INITIAL,
      department: activeDept || 'Design',
      reviewerId: activeMemberId || '',
    },
    { title: v => (!v || String(v).trim().length < 3) ? 'Title required (min 3 chars)' : null }
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const [res, memberRes] = await Promise.all([getTasks(), getMembers()]);
    setLoading(false);
    if (!res.ok) { setError(res.message); return; }
    const taskRows = res.data?.tasks ?? [];
    if (memberRes.ok) {
      const nextMembers = memberRes.data?.data ?? [];
      setMembers(nextMembers);
      const memberNames = new Map(nextMembers.map((member:any) => [member.id,member.name]));
      setTasks(taskRows.map((task:any) => ({
        ...task,
        assignedToName: memberNames.get(task.assignedToId) ?? task.assignedToName,
        reviewerName: memberNames.get(task.reviewerId) ?? task.reviewerName,
      })));
      if (!values.assignedToId && nextMembers[0]) set('assignedToId', nextMembers[0].id);
      if (!values.reviewerId && nextMembers[0]) set('reviewerId', nextMembers[0].id);
    } else setTasks(taskRows);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    if (!validate()) return;
    setSubmitting(true);
    const res = await createTask({
      ...values,
    });
    setSubmitting(false);
    if (!res.ok) { addToast('error', res.message); return; }
    addToast('success', 'Task created successfully');
    reset();
    setDrawerOpen(false);
    load();
  };

  const handleStatusUpdate = async (id: string, status: string) => {
    setStatusUpdating(id);
    const res = await updateTask(id, { status });
    setStatusUpdating(null);
    if (!res.ok) { addToast('error', res.message); return; }
    addToast('success', `Status updated to ${status}`);
    load();
  };

  const handleApprove = async (id: string, approvalStatus: 'Approved' | 'Rejected') => {
    const res = await approveTask(id, approvalStatus);
    if (!res.ok) { addToast('error', res.message); return; }
    addToast('success', `Task ${approvalStatus.toLowerCase()}`);
    load();
  };

  const getScopeSubtitle = () => {
    if (isTenantAdmin) return 'All Tenant Tasks — Full management & approval authority';
    if (activeDept === 'Design' && isManager) return 'Design Department (Section 09 Cross-Team View Active — all 3 design teams visible)';
    if (activeDept === 'Design' && isJunior) return 'My Assigned Design Tasks (Section 08 — Peer tasks restricted)';
    if (isManager) return `${activeDept} Department Tasks — Manager view & approval`;
    return 'My Assigned Tasks — Status update permitted';
  };

  const columns: Column<any>[] = [
    { key: 'workId', label: 'Work ID', width: 90 },
    { key: 'title', label: 'Title', sortable: true, width: 220 },
    { key: 'assignedToName', label: 'Assigned To', width: 140 },
    { key: 'department', label: 'Dept', width: 90 },
    { key: 'priority', label: 'Priority', width: 80, render: row => {
      const v = row.priority === 'Urgent' ? 'error' : row.priority === 'High' ? 'warning' : 'neutral';
      return <Badge variant={v as any}>{row.priority}</Badge>;
    }},
    { key: 'status', label: 'Status', width: 110, render: row => <Badge variant={statusVariant(row.status)}>{row.status}</Badge> },
    { key: 'dueDateTime', label: 'Due', width: 110, render: row =>
        row.dueDateTime ? new Date(row.dueDateTime).toLocaleDateString() : '—'
    },
    { key: 'approvalStatus', label: 'Approval', width: 100, render: row =>
        row.approvalStatus !== 'Not Required'
          ? <Badge variant={statusVariant(row.approvalStatus)}>{row.approvalStatus}</Badge>
          : <span style={{ color: 'var(--color-text-subtle)', fontSize: 'var(--font-size-xs)' }}>N/A</span>
    },
  ];

  return (
    <div className="page-body">
      <ToastList toasts={toasts} onRemove={removeToast} />
      <PageHeader
        title="Tasks Application"
        subtitle={getScopeSubtitle()}
        actions={canCreateTask ? <Button onClick={() => { reset(); setDrawerOpen(true); }}>New Task</Button> : undefined}
      />

      {/* RBAC Info Ribbon */}
      {isJunior && (
        <div style={{ padding: '8px 14px', background: 'var(--color-surface-2)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius)', marginBottom: 'var(--sp-4)', fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)' }}>
          📋 <strong>Junior Scope (Section 08):</strong> You can view and update the progress of your assigned work items. Peer team items and creation privileges are restricted.
        </div>
      )}

      {activeDept === 'Design' && isManager && (
        <div style={{ padding: '8px 14px', background: 'var(--color-surface-2)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius)', marginBottom: 'var(--sp-4)', fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)' }}>
          🔍 <strong>Design Manager Cross-Team Visibility (Section 09):</strong> You have read access across all 3 Design sub-teams. Peer reassignments require explicit delegation.
        </div>
      )}

      <DataTable
        columns={columns}
        data={tasks}
        loading={loading}
        error={error ?? undefined}
        onRetry={load}
        searchKeys={['title', 'assignedToName', 'department', 'workId']}
        emptyTitle="No tasks visible"
        emptySubtitle={isJunior ? "No tasks currently assigned to you" : "No tasks found for your access scope"}
        emptyAction={canCreateTask ? <Button onClick={() => setDrawerOpen(true)}>New Task</Button> : undefined}
        rowActions={row => {
          const isOwnAssigned = row.assignedToId === activeMemberId || row.assignedToId === session?.principal.id;
          const isPeerDesign = activeDept === 'Design' && isManager && !isOwnAssigned && row.reviewerId !== activeMemberId;

          // Juniors can only update status on their own task
          const canUpdateStatus = isTenantAdmin || (isManager && !isPeerDesign) || (isJunior && isOwnAssigned);
          // Only managers and admins can approve tasks
          const canApprove = (isTenantAdmin || isManager) && (row.reviewerId === activeMemberId || isTenantAdmin);

          if (isPeerDesign) {
            return (
              <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-subtle)', fontStyle: 'italic', paddingRight: 6 }}>
                Peer Read (§09)
              </span>
            );
          }

          return (
            <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end', flexWrap: 'wrap', alignItems: 'center' }}>
              {canUpdateStatus && row.status !== 'Completed' && (
                <SelectInput
                  value={row.status}
                  onChange={e => handleStatusUpdate(row.id, e.target.value)}
                  disabled={statusUpdating === row.id}
                  style={{ height: 26, fontSize: 'var(--font-size-xs)', padding: '0 6px', width: 110 }}
                >
                  {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                </SelectInput>
              )}

              {canApprove && row.approvalStatus === 'Pending' && (
                <div style={{ display: 'flex', gap: 4 }}>
                  <Button variant="secondary" size="sm" onClick={() => handleApprove(row.id, 'Approved')} title="Approve Task">✓ Approve</Button>
                  <Button variant="danger" size="sm" onClick={() => handleApprove(row.id, 'Rejected')} title="Reject Task">✗</Button>
                </div>
              )}
            </div>
          );
        }}
      />

      {/* Create Task Drawer */}
      <Drawer
        open={drawerOpen}
        title="Create Work Task"
        onClose={() => { reset(); setDrawerOpen(false); }}
        onSave={handleCreate}
        saving={submitting}
        saveLabel="Create Task"
        dirty={dirty}
      >
        <FormField label="Task Title" required error={errors.title}>
          <TextInput
            placeholder="e.g. Detailed Wall Section Specification"
            value={values.title}
            onChange={e => set('title', e.target.value)}
            hasError={!!errors.title}
            autoFocus
          />
        </FormField>
        <FormField label="Description">
          <TextareaInput
            placeholder="Technical details and deliverables"
            value={values.description}
            onChange={e => set('description', e.target.value)}
          />
        </FormField>

        {/* Section 08: Searchable Assigned To dropdown of the 11 members */}
        <FormField label="Assigned To (11 Team Members)" required>
          <SelectInput
            value={values.assignedToId}
            onChange={e => {
              const selectedMember = members.find(m => m.id === e.target.value);
              set('assignedToId', e.target.value);
              if (selectedMember) {
                set('department', selectedMember.department);
              }
            }}
          >
            {members.map(m => (
              <option key={m.id} value={m.id}>
                {m.name} — {m.department} Dept
              </option>
            ))}
          </SelectInput>
        </FormField>

        <FormField label="Reviewer / Approver" required>
          <SelectInput value={values.reviewerId} onChange={e => set('reviewerId', e.target.value)}>
            {members.map(m => <option key={m.id} value={m.id}>{m.name} — {m.department}</option>)}
          </SelectInput>
        </FormField>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-4)' }}>
          <FormField label="Department">
            <TextInput
              placeholder="e.g. Design"
              value={values.department}
              onChange={e => set('department', e.target.value)}
            />
          </FormField>
          <FormField label="Priority">
            <SelectInput value={values.priority} onChange={e => set('priority', e.target.value)}>
              {PRIORITIES.map(p => <option key={p} value={p}>{p}</option>)}
            </SelectInput>
          </FormField>
          <FormField label="Start Date">
            <TextInput type="date" value={values.startDate} onChange={e => set('startDate', e.target.value)} />
          </FormField>
          <FormField label="Due Date / Time">
            <TextInput type="datetime-local" value={values.dueDateTime} onChange={e => set('dueDateTime', e.target.value)} />
          </FormField>
        </div>
      </Drawer>
    </div>
  );
};
