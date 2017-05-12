[![License: AGPL-3](https://img.shields.io/badge/licence-AGPL--3-blue.svg "License: AGPL-3")](http://www.gnu.org/licenses/agpl-3.0-standalone.html)

# Odoo PayZen Payment

Odoo PayZen Payment is an open source plugin that links Odoo based e-commerce websites to PayZen secured payment gateway developped by [Lyra Network](https://www.lyra-network.com/).

For more information about PayZen, see https://payzen.eu/.

# Installation & Upgrade
Download module archive from [PayZen Github](https://github.com/payzen/plugin-odoo) releases tab or get it from https://payzen.io (menu E-commerce > Free payment plugins).

If already installed, you must delete the old payment_payzen folder. You will find already installed addons in either :

* [ODOO_ROOT_FOLDER]/server/odoo/addons/
* /var/lib/odoo/addons/[#version]/ (Linux only)
* `addons_path` defined in odoo.conf

Now unzip downloaded archive and copy the new payment_payzen folder to Odoo addons directory. Then you can :

* In your Odoo administrator interface, browse to "Configuration" tab. Here in, activate the developper mode. Then browse to "Applications" tab and click on "Update applications list".
* Or restart Odoo server with *sudo systemctl restart odoo* on Linux or by restarting Windows Odoo service. Odoo will update the applications list on startup.

In your Odoo administrator interface, browse to "Applications" tab, delete "Applications" filter from search field and search for "payzen" keyword. Click
"Install" (or "Upgrade") button of the "PayZen Payment Acquirer" module.

# Configuration

- Go to "Website Admin" tab.
- In "Configuration" section, expand "eCommerce" menu than click on "Payment Acquirers" entry.
- Click on button "Configure" of PayZen module.
- You can now enter PayZen credentials.

# Usage

If you have multiple Odoo's databases on your server, don't forget to set `dbfilter` parameter in odoo.conf. _You must launch one database only per URL_ because PayZen have to send back payment notification on the right database. Otherwise it will failed with a 404 error.
