// config/db.js
import "dotenv/config";
import mysql from "mysql2/promise";

// Helper function to parse MySQL connection string or use individual config
function parseConnectionString(connectionString) {
  if (!connectionString) return null;
  
  // If it's a MySQL connection string (mysql://user:pass@host:port/db)
  if (connectionString.startsWith('mysql://')) {
    return connectionString;
  }
  
  // If it's still a PostgreSQL connection string, we need to convert it
  // For now, we'll expect MySQL connection strings
  // Format: mysql://user:password@host:port/database
  return connectionString;
}

// Main Application Database - for students, officers, clubs, events, requirements, and admins
// Using single database configuration (all tables in one database)
const mainPoolConfig = parseConnectionString(process.env.MAIN_DATABASE_URL || process.env.DATABASE_URL) || {
  host: process.env.MAIN_DB_HOST || process.env.DB_HOST || 'localhost',
  user: process.env.MAIN_DB_USER || process.env.DB_USER || 'root',
  password: process.env.MAIN_DB_PASSWORD || process.env.DB_PASSWORD || '',
  database: process.env.MAIN_DB_NAME || process.env.DB_NAME || 'Uniclub',
  port: process.env.MAIN_DB_PORT || process.env.DB_PORT || 3306,
  ssl: process.env.MAIN_DATABASE_URL?.includes('ssl') ? { rejectUnauthorized: false } : undefined,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const mainPool = mysql.createPool(
  typeof mainPoolConfig === 'string'
    ? { uri: mainPoolConfig, waitForConnections: true, connectionLimit: 10, queueLimit: 0 }
    : mainPoolConfig
);

// Admin Database - using same database as main (all tables merged into one database)
// If ADMIN_DB_* settings are provided, use them; otherwise use MAIN_DB settings
const adminPoolConfig = parseConnectionString(process.env.ADMIN_DATABASE_URL) || {
  host: process.env.ADMIN_DB_HOST || mainPoolConfig.host || 'localhost',
  user: process.env.ADMIN_DB_USER || mainPoolConfig.user || 'root',
  password: process.env.ADMIN_DB_PASSWORD || mainPoolConfig.password || '',
  database: process.env.ADMIN_DB_NAME || mainPoolConfig.database || 'Uniclub',
  port: process.env.ADMIN_DB_PORT || mainPoolConfig.port || 3306,
  ssl: process.env.ADMIN_DATABASE_URL?.includes('ssl') ? { rejectUnauthorized: false } : undefined,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

// Use the same pool if both point to the same database, otherwise create separate pool
const useSamePool = (
  (typeof adminPoolConfig === 'string' ? adminPoolConfig : adminPoolConfig.database) === 
  (typeof mainPoolConfig === 'string' ? mainPoolConfig : mainPoolConfig.database)
) && (
  (typeof adminPoolConfig === 'string' ? adminPoolConfig : adminPoolConfig.host) === 
  (typeof mainPoolConfig === 'string' ? mainPoolConfig : mainPoolConfig.host)
);

const adminPool = useSamePool 
  ? mainPool 
  : mysql.createPool(
      typeof adminPoolConfig === 'string' 
        ? { uri: adminPoolConfig, waitForConnections: true, connectionLimit: 10, queueLimit: 0 }
        : adminPoolConfig
    );

// Wrapper to make MySQL pool compatible with PostgreSQL-style queries
// MySQL returns [rows, fields] but we want {rows} format
function wrapPool(pool, poolName) {
  return {
    query: async (sql, params) => {
      try {
        let mysqlSql = sql;
        let finalParams = params || [];
        
        // Convert PostgreSQL-style $1, $2, $3 to MySQL ? placeholders if needed
        if (params && params.length > 0 && sql.includes('$')) {
          // Replace $1, $2, etc. with ? in order
          mysqlSql = sql.replace(/\$(\d+)/g, '?');
        }
        
        // Convert PostgreSQL NULLS LAST to MySQL compatible syntax
        // NULLS LAST -> put NULLs at the end by using CASE in ORDER BY
        mysqlSql = mysqlSql.replace(/\s+NULLS\s+LAST/gi, '');
        mysqlSql = mysqlSql.replace(/\s+NULLS\s+FIRST/gi, '');
        
        // Convert PostgreSQL type casting ::int, ::text, etc. to MySQL CAST or remove
        mysqlSql = mysqlSql.replace(/::int/gi, '');
        mysqlSql = mysqlSql.replace(/::text/gi, '');
        mysqlSql = mysqlSql.replace(/::varchar/gi, '');
        mysqlSql = mysqlSql.replace(/::bigint/gi, '');
        
        // Convert PostgreSQL FILTER clause to MySQL CASE/SUM
        // COUNT(...) FILTER (WHERE ...) -> SUM(CASE WHEN ... THEN 1 ELSE 0 END)
        mysqlSql = mysqlSql.replace(/COUNT\s*\(\s*([^)]+)\s*\)\s+FILTER\s*\(\s*WHERE\s+([^)]+)\s*\)/gi, 
          'SUM(CASE WHEN $2 THEN 1 ELSE 0 END)');
        
        // Convert PostgreSQL INTERVAL '30 days' to MySQL INTERVAL 30 DAY
        mysqlSql = mysqlSql.replace(/INTERVAL\s+'(\d+)\s+days?'/gi, 'INTERVAL $1 DAY');
        mysqlSql = mysqlSql.replace(/INTERVAL\s+'(\d+)\s+months?'/gi, 'INTERVAL $1 MONTH');
        
        // Convert PostgreSQL date_trunc to MySQL DATE_FORMAT
        mysqlSql = mysqlSql.replace(/date_trunc\s*\(\s*'month'\s*,\s*([^)]+)\s*\)/gi, 
          "DATE_FORMAT($1, '%Y-%m-01')");
        
        // Convert PostgreSQL to_char to MySQL DATE_FORMAT
        mysqlSql = mysqlSql.replace(/to_char\s*\(\s*([^,]+)\s*,\s*'YYYY-MM'\s*\)/gi, 
          "DATE_FORMAT($1, '%Y-%m')");
        
        // Convert PostgreSQL ANY($1::int[]) to MySQL IN (...)
        // This is a simple conversion, may need more complex handling
        mysqlSql = mysqlSql.replace(/=\s*ANY\s*\(\s*\$(\d+)::int\[\]\s*\)/gi, 'IN ($1)');
        
        // Handle IF NOT EXISTS in ALTER TABLE (MySQL doesn't support IF NOT EXISTS in ALTER TABLE)
        if (/ALTER\s+TABLE.*ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS/i.test(mysqlSql)) {
          // Extract table name and column definition
          const alterMatch = mysqlSql.match(/ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+(.+)/i);
          if (alterMatch) {
            const tableName = alterMatch[1];
            const columnDef = alterMatch[2];
            // Check if column exists first
            try {
              const [columns] = await pool.execute(
                `SELECT COUNT(*) as count FROM information_schema.columns 
                 WHERE table_schema = DATABASE() 
                 AND table_name = ? 
                 AND column_name = ?`,
                [tableName, columnDef.split(/\s+/)[0]]
              );
              if (columns[0].count === 0) {
                // Column doesn't exist, add it
                mysqlSql = `ALTER TABLE ${tableName} ADD COLUMN ${columnDef}`;
              } else {
                // Column exists, return empty result
                return { rows: [], fields: [] };
              }
            } catch (checkError) {
              // If check fails, try to add the column anyway
              mysqlSql = `ALTER TABLE ${tableName} ADD COLUMN ${columnDef}`;
            }
          }
        }
        
        // Handle RETURNING clause (MySQL doesn't support RETURNING)
        const returningMatch = mysqlSql.match(/RETURNING\s+(.+)$/i);
        if (returningMatch) {
          const returningClause = returningMatch[1].trim();
          mysqlSql = mysqlSql.replace(/\s+RETURNING\s+.+$/i, '');
          
          // Determine the operation type
          const isInsert = /^INSERT\s+INTO/i.test(mysqlSql);
          const isUpdate = /^UPDATE/i.test(mysqlSql);
          const isDelete = /^DELETE\s+FROM/i.test(mysqlSql);
          
          // Execute the main query
          const [result] = await pool.execute(mysqlSql, finalParams);
          
          if (isInsert) {
            // For INSERT, get the last insert ID and select the row
            const insertId = result.insertId;
            if (insertId) {
              // Extract table name from INSERT INTO table_name
              const tableMatch = mysqlSql.match(/INSERT\s+INTO\s+(\w+)/i);
              if (tableMatch) {
                const tableName = tableMatch[1];
                const selectSql = `SELECT ${returningClause} FROM ${tableName} WHERE id = ?`;
                const [rows] = await pool.execute(selectSql, [insertId]);
                return { rows, fields: [] };
              }
            }
            return { rows: [], fields: [] };
          } else if (isUpdate || isDelete) {
            // For UPDATE/DELETE, we need to get affected rows
            // This is tricky - we'd need to parse the WHERE clause
            // For now, return empty rows (the calling code should handle this)
            // In practice, you might want to SELECT before UPDATE/DELETE
            return { rows: [], fields: [] };
          }
        }
        
        // Regular query execution
        const [rows, fields] = await pool.execute(mysqlSql, finalParams);
        return { rows, fields };
      } catch (error) {
        // Don't log expected/ignorable errors
        const isExpectedError = 
          error.code === 'ER_DUP_FIELDNAME' || // Duplicate column
          error.errno === 1060 || // Duplicate column
          error.code === 'ER_NO_SUCH_TABLE' || // Missing table
          error.errno === 1146 || // Missing table
          error.message?.includes('Duplicate column name') ||
          error.sqlMessage?.includes('Duplicate column name');
        
        if (!isExpectedError) {
          console.error(`Database error in ${poolName}:`, error);
        }
        throw error;
      }
    },
    connect: async () => {
      try {
        const connection = await pool.getConnection();
        connection.release();
        return connection;
      } catch (error) {
        throw error;
      }
    },
    end: async () => {
      await pool.end();
    }
  };
}

const wrappedAdminPool = wrapPool(adminPool, 'admin');
const wrappedMainPool = wrapPool(mainPool, 'main');

// Test connections
wrappedMainPool
  .connect()
  .then(() => console.log("✅ Connected to MySQL Database"))
  .catch((err) => console.error("❌ Database connection error:", err.message));

// Only test admin pool if it's different from main pool
if (!useSamePool) {
  wrappedAdminPool
  .connect()
    .then(() => console.log("✅ Connected to MySQL (Admin Database)"))
    .catch((err) => console.error("❌ Admin database connection error:", err.message));
}

// Helper function to get the appropriate pool based on table/context
export function getPool(tableName = null, context = null) {
  // Admin-related tables/queries go to admin database
  if (tableName === 'admins' || context === 'admin') {
    return wrappedAdminPool;
  }
  
  // All other tables go to main database
  return wrappedMainPool;
}

// Export both pools for direct access if needed
export { wrappedAdminPool as adminPool, wrappedMainPool as mainPool };

// Default export: main pool (for backward compatibility)
// Most queries will use this (students, officers, clubs, events, requirements)
export default wrappedMainPool;
