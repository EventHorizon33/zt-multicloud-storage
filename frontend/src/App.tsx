import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { StepUpProvider } from "./auth/StepUp";
import { Layout } from "./components/Layout";
import { Account } from "./screens/Account";
import { Admin } from "./screens/Admin";
import { Audit } from "./screens/Audit";
import { Dashboard } from "./screens/Dashboard";
import { Distribution } from "./screens/Distribution";
import { Files } from "./screens/Files";
import { Login } from "./screens/Login";
import { Security } from "./screens/Security";

function Gate() {
  const { status, can } = useAuth();
  if (status === "loading") return <div className="boot">Checking session…</div>;
  if (status === "anonymous") return <Login />;
  return (
    <StepUpProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="files" element={<Files />} />
          <Route path="distribution" element={<Distribution />} />
          <Route path="security" element={<Security />} />
          <Route path="audit" element={<Audit />} />
          <Route path="account" element={<Account />} />
          {/* Hidden for plain users; the server enforces user:list (admin) / kms:read (admin, auditor) regardless. */}
          {can("admin", "auditor") && <Route path="admin" element={<Admin />} />}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </StepUpProvider>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Gate />
      </AuthProvider>
    </BrowserRouter>
  );
}
