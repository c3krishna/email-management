#!/usr/bin/env node
// ============================================================
// archive-old-logs.mjs
// Phase 1: Long-term log archival to OCI Object Storage
// Schedule: 0 2 1 * * (1st of each month at 2am)
// Usage: node archive-old-logs.mjs [--dry-run] [--customer-id=1]
// ============================================================

import mysql from 'mysql2/promise';
import https from 'https';
import crypto from 'crypto';
import { createWriteStream, existsSync, mkdirSync, unlinkSync } from 'fs';
import { writeFile, readFile } from 'fs/promises';

const DRY_RUN     = process.argv.includes('--dry-run');
const CUSTOMER_ID = parseInt(process.argv.find(a => a.startsWith('--customer-id='))?.split('=')[1] || '0');

// ---- DB connections ----
const platformPool = mysql.createPool({
  host:     process.env.DB_HOST     || '10.180.0.84',
  user:     process.env.DB_USER     || 'mailmetrics',
  password: process.env.DB_PASSWORD || 'WorktualMailMetrics@123',
  database: 'threat_platform',
  waitForConnections: true,
  connectionLimit: 5,
});

const emailPool = mysql.createPool({
  host:     process.env.DB_HOST     || '10.180.0.84',
  user:     process.env.DB_USER     || 'mailmetrics',
  password: process.env.DB_PASSWORD || 'WorktualMailMetrics@123',
  database: 'worktual_email_campaign',
  waitForConnections: true,
  connectionLimit: 5,
});

// ---- OCI Config ----
const OCI = {
  tenancy:   process.env.OCI_TENANCY_ID     || '',
  user:      process.env.OCI_USER_ID        || '',
  fingerprint: process.env.OCI_FINGERPRINT  || '',
  privateKey:  process.env.OCI_PRIVATE_KEY  || '',
  region:    process.env.OCI_REGION         || 'ap-mumbai-1',
  namespace: process.env.OCI_NAMESPACE      || '',
  bucket:    process.env.OCI_ARCHIVE_BUCKET || 'email-log-archive',
};

function log(msg) {
  console.log(`[${new Date().toISOString().replace('T',' ').slice(0,19)}] ${msg}`);
}

// ---- Main ----
async function main() {
  log(`Archive job starting ${DRY_RUN ? '(DRY RUN)' : ''}`);

  // Get all customers with their retention settings
  const [customers] = await platformPool.query(`
    SELECT id, name, domain, retention_days
    FROM customers
    WHERE active = 1
    ${CUSTOMER_ID ? 'AND id = ' + CUSTOMER_ID : ''}
  `);

  log(`Processing ${customers.length} customer(s)`);

  for (const customer of customers) {
    await archiveCustomer(customer);
  }

  log('Archive job complete');
  process.exit(0);
}

async function archiveCustomer(customer) {
  log(`Customer: ${customer.name} (retention: ${customer.retention_days} days)`);

  // Find months older than retention_days
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - customer.retention_days);
  const cutoffYearMonth = `${cutoff.getFullYear()}-${String(cutoff.getMonth() + 1).padStart(2, '0')}`;

  log(`  Archiving data older than: ${cutoffYearMonth}`);

  // Get distinct year-months to archive
  const [months] = await emailPool.query(`
    SELECT
      DATE_FORMAT(log_datetime, '%Y-%m') AS year_month,
      COUNT(*) AS row_count,
      MIN(log_datetime) AS first_event,
      MAX(log_datetime) AS last_event
    FROM email_log_realtime
    WHERE customer_id = ?
      AND DATE_FORMAT(log_datetime, '%Y-%m') < ?
    GROUP BY DATE_FORMAT(log_datetime, '%Y-%m')
    ORDER BY year_month ASC
  `, [customer.id, cutoffYearMonth]);

  if (months.length === 0) {
    log(`  No data to archive for customer ${customer.id}`);
    return;
  }

  log(`  Found ${months.length} month(s) to archive`);

  for (const month of months) {
    await archiveMonth(customer, month);
  }
}

async function archiveMonth(customer, month) {
  const { year_month, row_count } = month;
  log(`  Archiving ${year_month} (${row_count.toLocaleString()} rows)`);

  // Check if already archived
  const [existing] = await platformPool.query(`
    SELECT id, status FROM archive_jobs
    WHERE customer_id = ? AND year_month = ? AND table_name = 'email_log_realtime'
  `, [customer.id, year_month]);

  if (existing.length > 0 && existing[0].status === 'done') {
    log(`  ${year_month} already archived — skipping`);
    return;
  }

  // Create/update job record
  let jobId;
  if (existing.length > 0) {
    jobId = existing[0].id;
    await platformPool.query(
      `UPDATE archive_jobs SET status='running', started_at=NOW() WHERE id=?`,
      [jobId]
    );
  } else {
    const [res] = await platformPool.query(`
      INSERT INTO archive_jobs (customer_id, year_month, table_name, row_count, status, started_at)
      VALUES (?, ?, 'email_log_realtime', ?, 'running', NOW())
    `, [customer.id, year_month, row_count]);
    jobId = res.insertId;
  }

  if (DRY_RUN) {
    log(`  [DRY RUN] Would archive ${row_count} rows for ${year_month}`);
    await platformPool.query(
      `UPDATE archive_jobs SET status='done', completed_at=NOW(), row_count=? WHERE id=?`,
      [row_count, jobId]
    );
    return;
  }

  try {
    // Fetch data
    const [rows] = await emailPool.query(`
      SELECT id, customer_id, server, log_datetime, event_type,
             mail_from, mail_to, subject, direction, status,
             dsn, reason, spam_score, classification, size_bytes
      FROM email_log_realtime
      WHERE customer_id = ?
        AND DATE_FORMAT(log_datetime, '%Y-%m') = ?
      ORDER BY log_datetime ASC
    `, [customer.id, year_month]);

    log(`  Fetched ${rows.length} rows for ${year_month}`);

    // Convert to CSV
    const header = 'id,customer_id,server,log_datetime,event_type,mail_from,mail_to,subject,direction,status,dsn,reason,spam_score,classification,size_bytes\n';
    const csvRows = rows.map(r => [
      r.id, r.customer_id, r.server, r.log_datetime,
      r.event_type, r.mail_from, r.mail_to,
      (r.subject || '').replace(/,/g, ';').replace(/\n/g, ' '),
      r.direction, r.status, r.dsn,
      (r.reason  || '').replace(/,/g, ';').replace(/\n/g, ' ').slice(0, 200),
      r.spam_score, r.classification, r.size_bytes
    ].join(','));

    const csvContent = header + csvRows.join('\n');
    const csvBytes   = Buffer.from(csvContent, 'utf8');
    const ociPath    = `customers/${customer.id}/${year_month}/email_log_realtime.csv`;

    log(`  Uploading to OCI: ${ociPath} (${Math.round(csvBytes.length / 1024)}KB)`);

    // Upload to OCI (use BackupVault OCI credentials)
    const uploaded = await uploadToOCI(csvBytes, ociPath);

    if (uploaded) {
      // Copy to archive table
      await platformPool.query(`
        INSERT IGNORE INTO email_log_archive
          (id, customer_id, server, log_datetime, event_type, mail_from, mail_to,
           subject, direction, status, dsn, reason, spam_score, classification, size_bytes)
        SELECT id, customer_id, server, log_datetime, event_type, mail_from, mail_to,
               subject, direction, status, dsn, reason, spam_score, classification, size_bytes
        FROM worktual_email_campaign.email_log_realtime
        WHERE customer_id = ? AND DATE_FORMAT(log_datetime, '%Y-%m') = ?
      `, [customer.id, year_month]);

      // Delete from hot table
      const [delResult] = await emailPool.query(`
        DELETE FROM email_log_realtime
        WHERE customer_id = ? AND DATE_FORMAT(log_datetime, '%Y-%m') = ?
      `, [customer.id, year_month]);

      log(`  Deleted ${delResult.affectedRows} rows from hot table`);

      // Mark done
      await platformPool.query(`
        UPDATE archive_jobs
        SET status='done', completed_at=NOW(), oci_path=?, oci_bucket=?, file_size_bytes=?
        WHERE id=?
      `, [ociPath, OCI.bucket, csvBytes.length, jobId]);

      log(`  ${year_month} archived successfully`);
    } else {
      throw new Error('OCI upload failed');
    }
  } catch (err) {
    log(`  ERROR archiving ${year_month}: ${err.message}`);
    await platformPool.query(
      `UPDATE archive_jobs SET status='failed', error_message=? WHERE id=?`,
      [err.message.slice(0, 500), jobId]
    );
  }
}

// ---- OCI Object Storage upload ----
async function uploadToOCI(data, objectPath) {
  if (!OCI.namespace || !OCI.tenancy) {
    log('  OCI not configured — saving locally instead');
    const dir = `/var/backups/email-archive/${objectPath.split('/').slice(0,-1).join('/')}`;
    mkdirSync(dir, { recursive: true });
    await writeFile(`/var/backups/email-archive/${objectPath}`, data);
    return true;
  }

  return new Promise((resolve, reject) => {
    const host   = `objectstorage.${OCI.region}.oraclecloud.com`;
    const path   = `/n/${OCI.namespace}/b/${OCI.bucket}/o/${encodeURIComponent(objectPath)}`;
    const date   = new Date().toUTCString();
    const digest = crypto.createHash('sha256').update(data).digest('base64');

    const signingStr = `date: ${date}\n(request-target): put ${path}\ncontent-length: ${data.length}\ncontent-type: text/csv\nx-content-sha256: ${digest}`;
    const signature  = crypto.createSign('RSA-SHA256').update(signingStr).sign(OCI.privateKey, 'base64');
    const authHeader = `Signature version="1",headers="date (request-target) content-length content-type x-content-sha256",keyId="${OCI.tenancy}/${OCI.user}/${OCI.fingerprint}",algorithm="rsa-sha256",signature="${signature}"`;

    const options = {
      hostname: host,
      path,
      method: 'PUT',
      headers: {
        'Date':              date,
        'Content-Type':      'text/csv',
        'Content-Length':    data.length,
        'x-content-sha256': digest,
        'Authorization':    authHeader,
      },
    };

    const req = https.request(options, res => {
      if (res.statusCode >= 200 && res.statusCode < 300) resolve(true);
      else reject(new Error(`OCI HTTP ${res.statusCode}`));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

main().catch(err => {
  log('FATAL: ' + err.message);
  process.exit(1);
});
