# Backdoor Scanner

A small WordPress plugin that checks a site for common backdoors attackers leave behind after a hack. It adds a page under **Tools > Backdoor Scanner**.

**[Try the infected demo site](https://playground.wordpress.net/?blueprint-url=https://raw.githubusercontent.com/aaronwsmith12/backdoor-scanner/main/demo/blueprint.json)**

The demo runs in your browser with WordPress Playground. Nothing is installed on a server. The planted code is harmless. Each payload decodes to `return;`.

## What it checks

- **Admin users.** Every administrator with their email and sign-up date.
- **Scheduled tasks.** Every cron job, plus the function and file it runs.
- **Suspicious code.** Lines in uploads and themes that use functions attackers rely on, like `eval` and `base64_decode`. Any PHP file in uploads is flagged, since that folder should only hold media.
- **Core files.** Compares `wp-admin`, `wp-includes` and the root files with the official WordPress.org checksums. Flags files that were changed, are missing or shouldn't be there.

## What the demo site finds, and how to fix it

The demo plants six things that are common on real hacked sites. Several of them work together, which is also common.

### 1. Rogue admin user
`wp_sysadmin` was added days after the real admin. Attackers add an admin so they can get back in after the malware is removed.

**Fix:** Delete the user and give their content to a real admin. Then reset every admin password and change the salts in `wp-config.php` so all sessions are logged out.

### 2. Changed core file
`wp-includes/default-filters.php` has one extra line at the end that loads another file. WordPress runs it on every page.

**Fix:** Don't edit core files by hand. Replace `wp-admin` and `wp-includes` with a clean copy of the same version, then confirm it:

```
wp core download --version=7.1.5 --skip-content --force
wp core verify-checksums
```

### 3. Extra file in wp-includes
`wp-includes/class-wp-cache-helper.php` has a core-sounding name but isn't part of WordPress.

**Fix:** `wp core download --force` overwrites core files but doesn't delete extra ones. Delete the `wp-admin` and `wp-includes` folders before downloading a fresh copy, or remove each file that `wp core verify-checksums` reports as "should not exist".

### 4. Malicious cron job
`wp_maintenance_check` runs every hour, and its code lives in the fake core file. Even if someone cleans the theme, this can put the infection back.

**Fix:** Remove the code first, then delete the event:

```
wp cron event delete wp_maintenance_check
```

### 5. Code hidden in the theme
`eval( base64_decode( ... ) )` was added to the end of the theme's `functions.php`. The base64 hides what the code does from a quick look.

**Fix:** Reinstall the theme from WordPress.org. For a custom theme, compare it with your Git repo or a backup from before the hack.

### 6. PHP file in uploads
`wp-content/uploads/2026/11/thumb.php` is named like an image thumbnail. Attackers often upload a file like this through a vulnerable form or plugin, then load it in the browser.

**Fix:** Delete it and block PHP from running in uploads. On Apache, add a `.htaccess` file in `wp-content/uploads`:

```
<Files *.php>
    Require all denied
</Files>
```

### After the cleanup
- Find how they got in. Outdated plugins and reused passwords are the usual causes. Check the server access logs around the dates the bad files appeared.
- Change the hosting, SFTP and database passwords too, not just WordPress.
- Scan again a day later to make sure nothing came back.

## Hardening checklist

- [ ] Keep WordPress, plugins and themes updated. Delete any you don't use.
- [ ] Use a strong, unique password and two-factor login for every admin.
- [ ] Keep the number of admin accounts small.
- [ ] Add `define( 'DISALLOW_FILE_EDIT', true );` to `wp-config.php` so code can't be edited from the dashboard.
- [ ] Block PHP in the uploads folder.
- [ ] Set file permissions to 644 for files and 755 for folders. Lock down `wp-config.php` to 600 or 640.
- [ ] Limit login attempts.
- [ ] Keep daily offsite backups and test that a restore works.
- [ ] Run `wp core verify-checksums` and `wp plugin verify-checksums --all` on a schedule.

## Limits

This is a quick first look, not a full malware scanner. It matches known function names, so heavily obfuscated code can get past it. It doesn't scan plugins or `mu-plugins` yet. A hacked site can also hide things from code running inside it, so check from the server too.

## Run it locally

With the infected demo:

```
npx @wp-playground/cli@latest server --blueprint=./demo/blueprint.json
```

With your local copy of the plugin:

```
npx @wp-playground/cli@latest server --mount=.:/wordpress/wp-content/plugins/backdoor-scanner --mount=./demo/uploads:/wordpress/wp-content/uploads
```