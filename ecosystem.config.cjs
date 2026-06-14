/**
 * PM2 Ecosystem Configuration
 *
 * Usage:
 *   pm2 start ecosystem.config.cjs
 *   pm2 restart watcher-mk1
 *   pm2 logs watcher-mk1
 *   pm2 stop watcher-mk1
 */

module.exports = {
  apps: [
    {
      name: 'watcher-mk1',
      script: 'dist/server/index.js',
      cwd: __dirname,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'production',
        PORT: 4000,
      },
      env_file: '.env',
      error_file: '/var/log/watcher-mk1/error.log',
      out_file: '/var/log/watcher-mk1/out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
    },
  ],
};
