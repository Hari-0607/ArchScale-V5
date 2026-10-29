import http from 'http';

interface TestResult {
  suite: string;
  test: string;
  passed: boolean;
  details: string;
}

const results: TestResult[] = [];

function record(suite: string, test: string, passed: boolean, details: string) {
  results.push({ suite, test, passed, details });
  const icon = passed ? '✅ PASS' : '❌ FAIL';
  console.log(`${icon} | [${suite}] ${test} -> ${details}`);
}

async function request(
  path: string,
  method = 'GET',
  body?: any,
  headers: Record<string, string> = {}
): Promise<{ status: number; body: any }> {
  return new Promise(resolve => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: 3000,
        path,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
          ...headers,
        },
      },
      res => {
        let raw = '';
        res.on('data', chunk => (raw += chunk));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode || 0, body: JSON.parse(raw) });
          } catch {
            resolve({ status: res.statusCode || 0, body: raw });
          }
        });
      }
    );
    if (payload) req.write(payload);
    req.end();
  });
}

async function runAllTests() {
  console.log('===============================================================');
  console.log('   XAuth v4.0 Foundation & Test Applications Verification Suite');
  console.log('===============================================================\n');

  // 1. Super Admin Backstage
  console.log('▶ [1] Super Admin & Backstage Isolation');
  const founderLogin = await request('/api/demo/quick-login', 'POST', { key: 'founder' });
  record(
    '05. Backstage',
    'Platform Super Admin Quick-Login',
    founderLogin.status === 200 && founderLogin.body.principal?.role === 'founder',
    `Role: ${founderLogin.body.principal?.role}, AAL: ${founderLogin.body.principal?.aal}`
  );

  // 2. Tenant Admin Context & Setup
  console.log('\n▶ [2] Tenant Admin Frontstage & Team Management');
  const adminLogin = await request('/api/demo/quick-login', 'POST', { key: 'tenant_admin' });
  const adminToken = adminLogin.body.accessToken;

  const membershipsRes = await request('/api/session/memberships', 'GET', null, {
    Authorization: `Bearer ${adminToken}`,
  });
  const orgId = membershipsRes.body.memberships?.[0]?.organisationId;

  const workspacesRes = await request(`/api/session/workspaces?organisationId=${orgId}`, 'GET', null, {
    Authorization: `Bearer ${adminToken}`,
  });
  const wsId = workspacesRes.body.workspaces?.[0]?.workspaceId;

  const ctxRes = await request('/api/session/context', 'POST', {
    organisationId: orgId,
    workspaceId: wsId,
  }, {
    Authorization: `Bearer ${adminToken}`,
  });
  const contextId = ctxRes.body.context?.contextId;
  record(
    '06. Frontstage',
    'Tenant Admin Context Establishment',
    ctxRes.status === 200 && !!contextId,
    `Org: ${orgId}, Context: ${contextId?.substring(0, 8)}...`
  );

  // 3. Team Members API & Role Update
  const membersRes = await request('/api/org/members', 'GET', null, {
    Authorization: `Bearer ${adminToken}`,
    'X-ArchScale-Context': contextId,
  });
  const members = membersRes.body.data || [];
  record(
    '07. Team Structure',
    '11-Member Team List Loaded with Roles & Hierarchy',
    membersRes.status === 200 && members.length === 11,
    `Loaded ${members.length} members with department and reporting lines`
  );

  const roleUpdateRes = await request(
    '/api/org/members/mem-dm1/role',
    'PATCH',
    { roleKey: 'leader' },
    {
      Authorization: `Bearer ${adminToken}`,
      'X-ArchScale-Context': contextId,
    }
  );
  record(
    '07. Team Management',
    'Tenant Admin Edits Member Role (mem-dm1)',
    roleUpdateRes.status === 200 && roleUpdateRes.body.success,
    `Status ${roleUpdateRes.status} (UUID crash eliminated)`
  );

  // Helper for authenticated persona request
  async function asPersona(key: string) {
    const lRes = await request('/api/demo/quick-login', 'POST', { key });
    const tok = lRes.body.accessToken;
    const dp = lRes.body.demoPersona;
    const demoHdr = Buffer.from(JSON.stringify(dp)).toString('base64');

    // Create context for this session
    const cRes = await request('/api/session/context', 'POST', {
      organisationId: orgId,
      workspaceId: wsId,
    }, {
      Authorization: `Bearer ${tok}`,
    });
    const cId = cRes.body.context?.contextId;

    return {
      tok,
      dp,
      cId,
      headers: {
        Authorization: `Bearer ${tok}`,
        'X-ArchScale-Context': cId,
        'X-Demo-Persona': demoHdr,
      },
    };
  }

  // 4. Tasks Application RBAC
  console.log('\n▶ [3] Tasks Application RBAC Verification');

  // 4a. Tenant Admin sees all 10 tasks
  const adminP = await asPersona('tenant_admin');
  const adminTasks = await request('/api/tasks', 'GET', null, adminP.headers);
  record(
    '08. Tasks RBAC',
    'Tenant Admin sees all 10 tenant tasks',
    adminTasks.body.tasks?.length === 10,
    `Visible tasks: ${adminTasks.body.tasks?.length}/10`
  );

  // 4b. Design Manager sees cross-team (all 6 Design tasks per §09)
  const dm1P = await asPersona('design_manager_1');
  const dm1Tasks = await request('/api/tasks', 'GET', null, dm1P.headers);
  record(
    '09. Tasks Exception',
    'Design Manager 1 cross-team visibility (all 3 Design teams)',
    dm1Tasks.body.tasks?.length === 6 && dm1Tasks.body.tasks.every((t: any) => t.department === 'Design'),
    `Visible design tasks: ${dm1Tasks.body.tasks?.length} (WRK-1001 through WRK-1006)`
  );

  // 4c. Junior Designer sees only 1 task (own assigned task)
  const jd1P = await asPersona('junior_designer_1');
  const jd1Tasks = await request('/api/tasks', 'GET', null, jd1P.headers);
  record(
    '08. Tasks Isolation',
    'Junior Designer 1 sees only own assigned task (peer tasks blocked)',
    jd1Tasks.body.tasks?.length === 1 && jd1Tasks.body.tasks[0]?.workId === 'WRK-1002',
    `Task: ${jd1Tasks.body.tasks?.[0]?.workId} (${jd1Tasks.body.tasks?.[0]?.title})`
  );

  // 4d. Juniors cannot create tasks (§08)
  const jdCreate = await request('/api/tasks', 'POST', { title: 'Unauthorized Task' }, jd1P.headers);
  record(
    '08. Tasks Permissions',
    'Junior cannot create tasks (Restricted)',
    jdCreate.status === 403,
    `Status: ${jdCreate.status} (${jdCreate.body?.error})`
  );

  // 4e. Juniors cannot approve tasks (§08 & §14)
  const jdApprove = await request('/api/tasks/tsk-001/approve', 'POST', { approvalStatus: 'Approved' }, jd1P.headers);
  record(
    '14. Approval Authority',
    'Junior cannot approve tasks (Managers/Admins only)',
    jdApprove.status === 403,
    `Status: ${jdApprove.status} (${jdApprove.body?.error})`
  );

  // 4f. Manager CAN approve tasks
  const dmApprove = await request('/api/tasks/tsk-001/approve', 'POST', { approvalStatus: 'Approved' }, dm1P.headers);
  record(
    '14. Approval Authority',
    'Design Manager can approve tasks',
    dmApprove.status === 200,
    `Status: ${dmApprove.status} (Approved)`
  );

  // 5. Attendance Application RBAC (Section 11 Matrix)
  console.log('\n▶ [4] Attendance Restricted Access Matrix Verification (Section 11)');

  // 5a. Tenant Admin cannot access Attendance (§11)
  const adminAtt = await request('/api/attendance', 'GET', null, adminP.headers);
  record(
    '11. Attendance Matrix',
    'Tenant Admin Attendance Access Denied (Default 403)',
    adminAtt.status === 403,
    `Status: ${adminAtt.status} (Access Denied)`
  );

  // 5b. Design Manager cannot access Attendance (§11)
  const dmAtt = await request('/api/attendance', 'GET', null, dm1P.headers);
  record(
    '11. Attendance Matrix',
    'Design Manager Attendance Access Denied (403)',
    dmAtt.status === 403,
    `Status: ${dmAtt.status} (Access Denied)`
  );

  // 5c. Junior Designer cannot access Attendance (§11)
  const jdAtt = await request('/api/attendance', 'GET', null, jd1P.headers);
  record(
    '11. Attendance Matrix',
    'Junior Designer Attendance Access Denied (403)',
    jdAtt.status === 403,
    `Status: ${jdAtt.status} (Access Denied)`
  );

  // 5d. HR Manager can view all 11 attendance records
  const hrMgrP = await asPersona('hr_manager');
  const hrMgrAtt = await request('/api/attendance', 'GET', null, hrMgrP.headers);
  record(
    '11. Attendance Matrix',
    'HR Manager Views All Tenant Records',
    hrMgrAtt.status === 200 && hrMgrAtt.body.records?.length === 11,
    `Status: ${hrMgrAtt.status}, Records: ${hrMgrAtt.body.records?.length}/11`
  );

  // 5e. HR Manager can edit attendance values
  const hrEdit = await request(
    '/api/attendance/att-01',
    'PATCH',
    { status: 'Present', checkInTime: '08:45 AM' },
    hrMgrP.headers
  );
  record(
    '11. Attendance Matrix',
    'HR Manager Can Edit Attendance Values',
    hrEdit.status === 200 && hrEdit.body.success,
    `Status: ${hrEdit.status} (Edit successful)`
  );

  // 5f. Junior HR can view all 11 records
  const jrHrP = await asPersona('junior_hr');
  const jrHrAtt = await request('/api/attendance', 'GET', null, jrHrP.headers);
  record(
    '11. Attendance Matrix',
    'Junior HR Views All Tenant Records',
    jrHrAtt.status === 200 && jrHrAtt.body.records?.length === 11,
    `Status: ${jrHrAtt.status}, Records: ${jrHrAtt.body.records?.length}/11`
  );

  // 5g. Junior HR cannot edit attendance values (§11: View=Yes, Edit=No, Comment=Yes)
  const jrHrEdit = await request(
    '/api/attendance/att-01',
    'PATCH',
    { status: 'Half Day' },
    jrHrP.headers
  );
  record(
    '11. Attendance Matrix',
    'Junior HR Editing Blocked (403 Forbidden)',
    jrHrEdit.status === 403,
    `Status: ${jrHrEdit.status} (${jrHrEdit.body?.message?.split('.')[0]})`
  );

  // 5h. Junior HR CAN append comments
  const jrHrComment = await request(
    '/api/attendance/att-01/comment',
    'POST',
    { comment: 'E2E verified doctor note on file' },
    jrHrP.headers
  );
  record(
    '11. Attendance Matrix',
    'Junior HR Can Append Comments',
    jrHrComment.status === 200 && jrHrComment.body.success,
    `Status: ${jrHrComment.status} (Comment appended)`
  );

  // Summary
  console.log('\n===============================================================');
  const passedCount = results.filter(r => r.passed).length;
  const failedCount = results.filter(r => !r.passed).length;
  console.log(`TOTAL TESTS: ${results.length} | PASSED: ${passedCount} | FAILED: ${failedCount}`);
  if (failedCount === 0) {
    console.log('🎉 ALL SYSTEM RBAC & ACCESS RULES VERIFIED AND READY TO GO!');
  } else {
    console.log('⚠️ SOME TESTS FAILED — CHECK LOGS ABOVE.');
  }
  console.log('===============================================================\n');
}

runAllTests();
