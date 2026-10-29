import React, { useEffect, useState, useCallback } from 'react';
import { getTasks, createTask, updateTask, approveTask } from '../../api/client';
import { DataTable, Column } from '../../components/DataTable';
import { PageHeader } from '../../components/PageHeader';
import { Badge, statusVariant } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Drawer } from '../../components/Drawer';
import { FormField, TextInput, SelectInput, TextareaInput } from '../../components/FormField';
import { useToast } from '../../hooks/useToast';
import { ToastList } from '../../components/Toast';
import { useForm } from '../../hooks/useForm';

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
  title: '', description: '', assignedToId: '', department: '', reviewerId: '',
  startDate: '', dueDateTime: '', priority: 'Normal',
};

export const TasksPage: React.FC = () => {
  const { toasts, addToast, removeToast } = useToast();
  const [tasks, setTasks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [statusUpdating, setStatusUpdating] = useState<string | null>(null);

  const { values, errors, set, validate, reset, submitting, setSubmitting, dirty } = useForm<TaskForm>(
    INITIAL,
    { title: v => (!v || String(v).trim().length < 3) ? 'Title required (min 3 chars)' : null }
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const res = await getTasks();
    setLoading(false);
    if (!res.ok) { setError(res.message); return; }
    setTasks(res.data?.tasks ?? []);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    if (!validate()) return;
    setSubmitting(true);
    const res = await createTask(values);
    setSubmitting(false);
    if (!res.ok) { addToast('error', res.message); return; }
    addToast('success', 'Task created');
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

  const columns: Column<any>[] = [
    { key: 'workId', label: 'ID', width: 80 },
    { key: 'title', label: 'Title', sortable: true, width: 200 },
    { key: 'assignedToName', label: 'Assigned To', width: 140 },
    { key: 'department', label: 'Dept', width: 100 },
    { key: 'priority', label: 'Priority', width: 80, render: row => {
      const v = row.priority === 'Urgent' ? 'error' : row.priority === 'High' ? 'warning' : 'neutral';
      return <Badge variant={v as any}>{row.priority}</Badge>;
    }},
    { key: 'status', label: 'Status', width: 110, render: row => <Badge variant={statusVariant(row.status)}>{row.status}</Badge> },
    { key: 'dueDateTime', label: 'Due', width: 120, render: row =>
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
        title="Tasks"
        subtitle="Track and manage work items"
        actions={<Button onClick={() => { reset(); setDrawerOpen(true); }}>New Task</Button>}
      />

      <DataTable
        columns={columns}
        data={tasks}
        loading={loading}
        error={error ?? undefined}
        onRetry={load}
        searchKeys={['title', 'assignedToName', 'department']}
        emptyTitle="No tasks"
        emptySubtitle="Create your first task to get started"
        emptyAction={<Button onClick={() => setDrawerOpen(true)}>New Task</Button>}
        rowActions={row => (
          <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end', flexWrap: 'wrap' }}>
            {row.status !== 'Completed' && (
              <SelectInput
                value={row.status}
                onChange={e => handleStatusUpdate(row.id, e.target.value)}
                disabled={statusUpdating === row.id}
                style={{ height: 26, fontSize: 'var(--font-size-xs)', padding: '0 6px', width: 110 }}
              >
                {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
              </SelectInput>
            )}
            {row.approvalStatus === 'Pending' && (
              <>
                <Button variant="secondary" size="sm" onClick={() => handleApprove(row.id, 'Approved')}>✓</Button>
                <Button variant="danger" size="sm" onClick={() => handleApprove(row.id, 'Rejected')}>✗</Button>
              </>
            )}
          </div>
        )}
      />

      <Drawer
        open={drawerOpen}
        title="New Task"
        onClose={() => { reset(); setDrawerOpen(false); }}
        onSave={handleCreate}
        saving={submitting}
        saveLabel="Create Task"
        dirty={dirty}
      >
        <FormField label="Title" required error={errors.title}>
          <TextInput
            placeholder="Task title"
            value={values.title}
            onChange={e => set('title', e.target.value)}
            hasError={!!errors.title}
            autoFocus
          />
        </FormField>
        <FormField label="Description">
          <TextareaInput
            placeholder="Optional details"
            value={values.description}
            onChange={e => set('description', e.target.value)}
          />
        </FormField>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-4)' }}>
          <FormField label="Department">
            <TextInput placeholder="e.g. Design" value={values.department} onChange={e => set('department', e.target.value)} />
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

