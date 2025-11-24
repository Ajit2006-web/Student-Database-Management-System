const mysql = require('mysql2');

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',      // ⬅️ change if your MySQL user is different
  password: 'Ajit#2006',      // ⬅️ put your MySQL password if you have one
  database: 'student_db'
});

module.exports = pool.promise();
