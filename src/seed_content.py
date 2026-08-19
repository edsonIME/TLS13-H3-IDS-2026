#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
seed_content.py
===============

Seed the victim WordPress (NB1) with realistic content so that BENIGN browsing
has real depth. Without a populated site, a model may learn incidental artifacts
of traffic generation instead of normal-vs-attack behavior.
    [Bad Design Smells in Benchmark NIDS Datasets, §6.3:
     "include the normal usage of the service being attacked"]

HOW IT WORKS
------------
It drives the official `wordpress:cli` (wp-cli) image as a throwaway container
that shares the running WordPress container's filesystem and Docker network, so
no wp-cli install is needed on the host. It will install WordPress if the wizard
was not completed yet, then create users, categories, tags, posts and comments.

RUN THIS ON NB1 (the victims host), inside the compose project directory. Seed
BOTH WordPress sites (blog.lab and shop.lab) so the benign generator has two
distinct, populated services to browse:
    python3 seed_content.py --url https://blog.lab --admin-pass 'ChangeMe!123'
    python3 seed_content.py --service wordpress2 --url https://shop.lab \
        --db-host db2 --db-name wp2 --admin-pass 'ChangeMe!123'

SAFETY / SCOPE
--------------
Operates only on your own lab WordPress. Not an attack tool.
"""

import argparse
import subprocess
import sys
import time


def sh(cmd, capture=False, check=True):
    """Run a shell command (list form). Return stdout when capture=True."""
    print("  $", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=capture, text=True)
    if check and result.returncode != 0:
        if capture:
            sys.stderr.write(result.stderr or "")
        sys.exit("Command failed: {}".format(" ".join(cmd)))
    return result.stdout.strip() if capture else ""


def compose_container(service):
    """Resolve the container ID of a docker-compose service (e.g. wordpress)."""
    cid = sh(["docker", "compose", "ps", "-q", service], capture=True)
    if not cid:
        sys.exit("Could not find running service '{}'. Run from the compose "
                 "project directory after 'docker compose up -d'.".format(service))
    return cid


def container_network(cid):
    """Return the first Docker network name attached to a container."""
    fmt = "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}"
    nets = sh(["docker", "inspect", "-f", fmt, cid], capture=True)
    return nets.split()[0]


class WpCli:
    """Thin wrapper that runs wp-cli against the live WordPress container."""

    def __init__(self, wp_container, network, db_env):
        self.wp_container = wp_container
        self.network = network
        self.db_env = db_env          # DB vars wp-cli needs to read wp-config.php

    def __call__(self, *args, capture=False, check=True):
        # A disposable wp-cli container reusing the WordPress volumes + network.
        # User 33 == www-data, which owns the WordPress files.
        # The WordPress image evaluates wp-config.php from these env vars, so the
        # wp-cli container MUST receive the same DB variables or it cannot reach
        # the database (wp db check / core install would fail).
        env_flags = []
        for key, value in self.db_env.items():
            env_flags += ["-e", "{}={}".format(key, value)]
        base = ["docker", "run", "--rm",
                "--network", self.network,
                "--volumes-from", self.wp_container] + env_flags + [
                "-u", "33:33", "wordpress:cli",
                "wp", "--path=/var/www/html"]
        return sh(base + list(args), capture=capture, check=check)


def wait_for_db(wp, retries=30):
    """Block until WordPress can reach its database; ABORT if it never does.

    Continuing past an unreachable DB produced confusing half-seeded state and a
    non-reproducible victim; fail fast instead [audit 21].
    """
    for i in range(retries):
        out = wp("db", "check", capture=True, check=False)
        if "Success" in out or "database" in out.lower():
            return
        print("  waiting for database... ({}/{})".format(i + 1, retries))
        time.sleep(5)
    sys.exit("ABORT: database not reachable after {} retries; not seeding a "
             "half-broken victim. Check the db container / credentials. [audit 21]".format(retries))


def ensure_installed(wp, url, title, admin_user, admin_pass, admin_email):
    """Install WordPress non-interactively if the wizard was not completed."""
    installed = wp("core", "is-installed", capture=True, check=False)
    # `is-installed` returns empty stdout and exit 0 when installed; on failure
    # (not installed) it exits non-zero. We probe via a follow-up option read.
    check = wp("option", "get", "siteurl", capture=True, check=False)
    if check.startswith("http"):
        print("  WordPress already installed:", check)
        return
    print("  installing WordPress...")
    wp("core", "install",
       "--url={}".format(url),
       "--title={}".format(title),
       "--admin_user={}".format(admin_user),
       "--admin_password={}".format(admin_pass),
       "--admin_email={}".format(admin_email),
       "--skip-email")


def _count(wp, post_type):
    try:
        return int(wp("post", "list", "--post_type={}".format(post_type),
                      "--format=count", capture=True) or "0")
    except ValueError:
        return 0


def seed(wp, users, posts, comments, pages, force=False):
    """Create users, taxonomy, posts, pages and comments IDEMPOTENTLY [audit 17].

    Re-running must not keep appending posts (that changes IDs/links and makes the
    victim non-reproducible). We generate only the SHORTFALL up to the target
    counts; --force regenerates from scratch. For a publication, snapshot the DB
    (mysqldump) after seeding and version it so every run starts from one state.
    """
    wp("option", "update", "blog_public", "0", check=False)

    if force:                                            # actually RESET, not just re-run [audit 21]
        print("  --force: deleting existing posts/pages/comments...")
        for pt in ("post", "page"):
            ids = wp("post", "list", "--post_type={}".format(pt), "--format=ids",
                     capture=True, check=False)
            if ids.strip():
                wp("post", "delete", *ids.split(), "--force", check=False)
        cids = wp("comment", "list", "--format=ids", capture=True, check=False)
        if cids.strip():
            wp("comment", "delete", *cids.split(), "--force", check=False)

    have_posts, have_pages = _count(wp, "post"), _count(wp, "page")
    if not force and have_posts >= posts and have_pages >= pages:
        print("  already seeded (posts={} pages={} >= targets); skipping [audit 17]."
              .format(have_posts, have_pages))
        _print_content_summary(wp)
        return

    print("  creating users up to {}...".format(users))
    for i in range(1, users + 1):
        wp("user", "create", "user{}".format(i),
           "user{}@blog.lab".format(i), "--role=author",
           "--user_pass=Passw0rd!{}".format(i), check=False)  # dup user => harmless fail

    print("  creating categories and tags...")
    for cat in ["news", "tutorials", "reviews", "opinion"]:
        wp("term", "create", "category", cat, check=False)
    for tag in ["python", "network", "security", "linux", "web"]:
        wp("term", "create", "post_tag", tag, check=False)

    need_posts = max(0, posts - have_posts)
    print("  generating {} posts (have {}, target {})...".format(need_posts, have_posts, posts))
    if need_posts:
        wp("post", "generate", "--count={}".format(need_posts),
           "--post_type=post", "--post_status=publish")

    need_pages = max(0, pages - have_pages)
    print("  generating {} pages (have {}, target {})...".format(need_pages, have_pages, pages))
    if need_pages:
        wp("post", "generate", "--count={}".format(need_pages), "--post_type=page")

    have_comments = int(wp("comment", "list", "--format=count", capture=True, check=False) or "0")
    need_comments = max(0, comments - have_comments)
    print("  generating {} comments (have {}, target {})...".format(
        need_comments, have_comments, comments))
    if need_comments:
        wp("comment", "generate", "--count={}".format(need_comments), check=False)

    _print_content_summary(wp)


def _print_content_summary(wp):
    print("  content summary: posts={} pages={} comments={} [audit 17]".format(
        _count(wp, "post"), _count(wp, "page"),
        wp("comment", "list", "--format=count", capture=True, check=False)))
    print("  For a reproducible victim, snapshot now:  "
          "mysqldump ... > wp_seed.sql  (version it) [audit 17].")


def main():
    ap = argparse.ArgumentParser(description="Seed the lab WordPress with content.")
    ap.add_argument("--service", default="wordpress",
                    help="compose service name of WordPress (default: wordpress)")
    ap.add_argument("--url", default="https://blog.lab")
    ap.add_argument("--title", default="Lab Blog")
    ap.add_argument("--admin-user", default="admin")
    ap.add_argument("--admin-pass", default="ChangeMe!123")
    ap.add_argument("--admin-email", default="admin@blog.lab")
    ap.add_argument("--users", type=int, default=6)
    ap.add_argument("--posts", type=int, default=300)
    ap.add_argument("--pages", type=int, default=15)
    ap.add_argument("--comments", type=int, default=500)
    ap.add_argument("--force", action="store_true",
                    help="regenerate content even if the site already meets the targets "
                         "(default: idempotent — only fill the shortfall) [audit 17]")
    # DB variables must match docker-compose.yml (service wordpress).
    ap.add_argument("--db-host", default="db")
    ap.add_argument("--db-user", default="root")
    ap.add_argument("--db-pass", default="lab")
    ap.add_argument("--db-name", default="wp")
    args = ap.parse_args()

    cid = compose_container(args.service)
    net = container_network(cid)
    db_env = {"WORDPRESS_DB_HOST": args.db_host, "WORDPRESS_DB_USER": args.db_user,
              "WORDPRESS_DB_PASSWORD": args.db_pass, "WORDPRESS_DB_NAME": args.db_name}
    wp = WpCli(cid, net, db_env)

    wait_for_db(wp)
    ensure_installed(wp, args.url, args.title, args.admin_user,
                     args.admin_pass, args.admin_email)
    seed(wp, args.users, args.posts, args.comments, args.pages, force=args.force)
    print("Seeding complete. The benign generator now has real content to browse.")


if __name__ == "__main__":
    main()
