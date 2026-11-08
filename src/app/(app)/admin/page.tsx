import { pageUser } from "@/lib/session";
import { listDepartments, listUsers } from "@/lib/services/admin";
import { NewUserForm, SweepButton, UserToggle } from "@/components/AdminPanels";
import { PageHead, shortDate } from "@/components/ui";

export default async function AdminPage() {
  const user = await pageUser("users:admin");
  const [users, depts] = await Promise.all([listUsers(user), listDepartments(user)]);
  return (
    <>
      <PageHead title="Administration" sub="User accounts, roles and maintenance jobs.">
        <SweepButton />
      </PageHead>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>E-mail</th><th>Department</th><th>Last sign-in</th><th>Status</th><th>Role / access</th></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={String(u.user_id)}>
                <td>{u.full_name}</td><td className="mono">{u.email}</td><td>{u.department}</td>
                <td>{u.last_login_at ? shortDate(u.last_login_at) : "never"}</td>
                <td>{Number(u.is_active) ? "Active" : <span className="badge sync-FAILED">Disabled</span>}</td>
                <td><UserToggle userId={Number(u.user_id)} isActive={Boolean(Number(u.is_active))} role={String(u.role)} self={Number(u.user_id) === user.id} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card" style={{ marginTop: 20 }}>
        <h2>Create a user</h2>
        <NewUserForm departments={depts.map((d) => ({ id: Number(d.department_id), name: String(d.name) }))} />
      </div>
    </>
  );
}
