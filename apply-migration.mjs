import mysql from 'mysql2/promise';
import fs from 'fs';
import { URL } from 'url';

const dbUrl = process.env.DATABASE_URL;
const url = new URL(dbUrl);

const connection = await mysql.createConnection({
  host: url.hostname,
  user: url.username,
  password: url.password,
  database: url.pathname.slice(1),
  ssl: {
    rejectUnauthorized: false
  },
  waitForConnections: true,
  connectionLimit: 1,
  queueLimit: 0,
});

const sql = fs.readFileSync('./drizzle/migration_clean.sql', 'utf-8');
const statements = sql.split(';').filter(s => s.trim());

for (const statement of statements) {
  if (statement.trim()) {
    try {
      console.log(`Executing: ${statement.substring(0, 50)}...`);
      await connection.execute(statement);
      console.log('✓ Success');
    } catch (error) {
      console.error('✗ Error:', error.message);
    }
  }
}

await connection.end();
console.log('Migration complete!');
