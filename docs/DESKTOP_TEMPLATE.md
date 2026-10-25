# Future Ubuntu XFCE desktop template

This procedure is for a **new, explicitly authorized disposable builder VM** and
new test clones. No desktop deployment, package installation or credential
change is part of the console firewall work. Preserve existing VMs and their
credentials. The graphical login password is a guest account secret, separate
from CloudStack/Dirigentenstab login, console session tickets and SSH private keys.

## Build and configure

1. Deploy a new builder from the approved Ubuntu cloud image with cloud-init,
   a dedicated non-root account and a fresh SSH key. For managed Dirigentenstab
   VMs, the existing backend creates **dirigent**, pins the guest host key and
   disables SSH password/root login. Use an explicitly approved build template
   if guest sudo is required. Do not enable root SSH or change security groups
   beyond the existing authorized application-to-guest SSH path.
2. Inside that builder only, install the X11 desktop and display manager:

   ```sh
   sudo apt-get update
   sudo apt-get install --no-install-recommends xfce4 xorg lightdm lightdm-gtk-greeter dbus-x11
   sudo systemctl enable lightdm
   sudo systemctl set-default graphical.target
   ```

   If asked for a display manager, choose LightDM. Select the Xfce session in its
   greeter; keep autologin disabled. XFCE is available in Ubuntu's universe
   repository ([packages](https://packages.ubuntu.com/search?keywords=xfce4)).
3. Keep an emulated graphical display connected to CloudStack's VNC console.
   For this new VM, set CloudStack's per-VM **video.hardware=qxl** and
   **video.ram=65536** (KiB) while stopped, using the supported VM settings UI/API;
   install `xserver-xorg-video-qxl` in the builder. Verify the generated libvirt
   video model after starting. If the deployed CloudStack version does not
   expose those settings, stop and check that version's supported settings;
   do not edit generated libvirt XML or change global host defaults. QXL is a
   reasonable starting point for XFCE; test 1280×800 or 1280×1024 in the console.
   Keep physical/vGPU assignment out of this basic desktop template. See the
   [CloudStack per-VM video setting change](https://github.com/apache/cloudstack/pull/5513).
4. On the new builder, assign the dedicated account its own console password
   interactively: `sudo passwd dirigent`. Store it in a password manager, not in
   chat, scripts, user-data or the reusable image. Keep `PasswordAuthentication
   no`, `KbdInteractiveAuthentication no` and `PermitRootLogin no` effective in
   sshd, validating with `sudo sshd -T` before closing the working key session.
   `ssh_pwauth: false` remains set in cloud-init. An account password permits
   graphical/PAM console login while SSH remains key-only; see
   [cloud-init user/password settings](https://docs.cloud-init.io/en/latest/reference/modules.html#users-and-groups).
5. Verify SSH key login, LightDM login as the non-root user, XFCE screen updates,
   keyboard/mouse and logout through a fresh CloudStack console. A text login or
   black screen alone is not evidence that the firewall failed. Check
   `systemctl status lightdm`, `journalctl -b -u lightdm`, `loginctl` and Xorg logs;
   inspect `lspci`/`xrandr` from the graphical session if video is wrong.

## Sanitize, capture and test a clone

Before capture, **inside the disposable builder only**, remove temporary build
files, saved browser sessions, licensing tokens and other machine-specific
secrets. Discard and lock the test console password hash with
`sudo usermod --password '!' dirigent`; remove
builder SSH authorized keys and SSH host keys, then run
`sudo cloud-init clean --logs --machine-id` and shut down immediately. Use the
CloudStack stop operation and wait for the VM to be Stopped before creating a
**private** template from its root volume. Do not boot the sanitized builder again
before capture. See [cloud-init image cleaning](https://docs.cloud-init.io/en/latest/reference/cli.html#clean).

Deploy a second new VM from that private template with fresh backend-generated
SSH credentials, host-key pin and machine identity. The existing managed
cloud-init deliberately locks `dirigent` on first boot. After cloud-init finishes,
an authorized guest administrator must set a **new per-clone** console password
interactively using `sudo passwd dirigent` through an authorized SSH session.
Do not reuse the builder's password or enable SSH password authentication. If
guest sudo is unavailable, arrange an authorized provisioning path before
deployment; the current application does not accept arbitrary custom user-data.

Repeat key-only SSH and GUI console login checks on the clone, including a clone
reboot. Confirm its SSH host key, client key and machine-id differ from the
builder's. Confirm video settings survived template capture; otherwise apply
them to this new clone through CloudStack before starting it. Only then designate
the private template reusable. A template with a locked account is expected;
password assignment belongs to each newly authorized desktop deployment.
