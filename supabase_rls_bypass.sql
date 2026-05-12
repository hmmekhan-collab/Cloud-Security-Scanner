-- Run this SQL in your Supabase SQL Editor to explicitly allow all operations.

-- First, ensure RLS is enabled so we can attach a policy to it
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE breach_checks ENABLE ROW LEVEL SECURITY;

-- Then, create policies that allow ALL anon/authenticated users to do anything (Insert, Select, Update, Delete)
CREATE POLICY "Allow All operations for users" ON users FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow All operations for cloud_accounts" ON cloud_accounts FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow All operations for scan_results" ON scan_results FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow All operations for findings" ON findings FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow All operations for reports" ON reports FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow All operations for breach_checks" ON breach_checks FOR ALL USING (true) WITH CHECK (true);

-- Also explicitly grant standard permission to the anon and authenticated roles
GRANT ALL ON ALL TABLES IN SCHEMA public to anon;
GRANT ALL ON ALL TABLES IN SCHEMA public to authenticated;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public to anon;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public to authenticated;
