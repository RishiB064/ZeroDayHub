import Link from "next/link";

export default function Forbidden() {
  return (
    <div className="login">
      <div className="card">
        <h1>Access denied</h1>
        <p className="sub">Your role does not have permission to open that page.</p>
        <Link className="btn" href="/">Back to the dashboard</Link>
      </div>
    </div>
  );
}
