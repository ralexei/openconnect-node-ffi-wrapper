// Modules to control application life and create native browser window
const BrowserWindow = require('electron').BrowserWindow
const app = require('electron').app;
const path = require('path')
const ffi = require('ffi');
const ref = require('ref');
const ArrayType = require('ref-array');
const log = require('electron-log');
var dialog = require('electron').dialog;
const Struct = require('ref-struct');
const fs = require('fs');

// Keep a global reference of the window object, if you don't, the window will
// be closed automatically when the JavaScript object is garbage collected.
let mainWindow
let myLib

// acceptedCertType.defineProperty('next', ref.refType(acceptedCertType));

const oc_form_opt = Struct({
  next: 'pointer',
  type: ref.types.int,
  name: 'string',
  label: 'string',
  _value: 'string',
  flags: ref.types.uint,
  reserved: 'void *'
});

// oc_form_opt.defineProperty('next', ref.refType(oc_form_opt));

const oc_auth_form = Struct({
  banner: 'string',
  message: 'string',
  error: 'string',
  auth_id: 'string',
  method: 'string',
  action: 'string',
  opts: ref.refType(oc_form_opt),
  authgroup_opt: 'pointer',
  authgroup_selection: ref.types.int
});

process.on('uncaughtException', function (error) {
  log.log('--------------------------------------------------------------');
  var errorMsg;
  if (error && error.stack) {
    errorMsg = error.stack;
  } else {
    errorMsg = error;
  }
  log.log(errorMsg);
  dialog.showMessageBox(null, {
    type: 'error',
    buttons: ['Exit'],
    title: '',
    message: 'Error occured in main process:\n\n' + errorMsg,
  }, function () {
    app.quit();
  });
});

function createWindow() {
  // Create the browser window.
  mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js')
    }
  })
  mainWindow.webContents.openDevTools();


  // and load the index.html of the app.
  mainWindow.loadFile('index.html')

  setTimeout(oc_connect, 5000);

  mainWindow.on('closed', function () {
    mainWindow = null
  })
}

function oc_connect() {
  const voidPointer = ref.refType(ref.types.void);
  const stringArray = ArrayType('string');

  var process_auth_form_cb = ffi.Callback('int', ['void *', ref.refType(oc_auth_form)], function (vpninfo, _form) {
    // let opt;
    let form = ref.deref(_form);
    let opts = form.opts;
    log.log('Processing auth form');

    while (opts.deref()) {
      var optValue = opts.deref();

      log.log('Current form opt to process', JSON.stringify(optValue));

      if (optValue.flags & 0x0001)
        continue;

      if (optValue.type == 1) {
        log.log("Text form for" + optValue.type);

        if (optValue.name == 'username') {
          myLib.openconnect_set_option_value(opts, "13000000012");

          opts = optValue.next;

          continue;
        }
      } else if (optValue.type == 2) {
        log.log("Password form: " + optValue.name);

        if (optValue.name == 'password') {
          myLib.openconnect_set_option_value(opts, "d93ae65992caf6a8751e334d0a716ad8");

          opts = optValue.next;

          continue;
        }
      } else {
        log.log('Unknownt type ' + optValue.type);
      }
    }
  });
  var write_progress_cb = ffi.Callback('void', ['void *', 'int', 'string', stringArray], function(vpninfo, level, format, ...args) {
    // log.log(format);
    fs.appendFile('vpn.log', format, () => {});

  });
  var validate_peer_cert_cb = ffi.Callback('int', ['void *', 'string'], function(_vpninfo, reason) {
    myLib.openconnect_get_peer_cert_hash(_vpninfo);

    log.log("Certificate from VPN server " + myLib.openconnect_get_hostname(_vpninfo) + " failed verification.");
    log.log("Reason: ", reason)
    log.log("To trust that server in future, perhaps add that to your command line:");
    log.log("Accepting new servcert");
  });

  myLib = ffi.Library('libopenconnect-5', {
    'openconnect_get_version': ["string", []],
    'openconnect_vpninfo_new': ['void *', ['string', 'pointer', 'pointer', 'pointer', 'pointer', 'void *']],
    'openconnect_init_ssl': ['int', []],
    'openconnect_parse_url': ['int', ['void *', 'string']],
    'openconnect_set_reported_os': ['int', ['void *', 'string']],
    'openconnect_set_protocol': ['int', ['void *', 'string']],
    'openconnect_obtain_cookie': ['int', ['void *']],
    'openconnect_set_option_value': ['int', ['void *', 'string']],
    'openconnect_make_cstp_connection': ['int', ['void *']],
    'openconnect_setup_dtls': ['int', ['void *', 'int']],
    'openconnect_setup_tun_device': ['int', ['void *', 'string', 'string']],
    'openconnect_get_port': ['int', ['void *']],
    'openconnect_get_hostname': ['string', ['void *']],
    'openconnect_get_peer_cert_hash': ['string', ['void *']],
    'openconnect_check_peer_cert_hash': ['int', ['void *', 'string']],
    'openconnect_mainloop': ['int', ['void *', 'int', 'int']]
    // 'openconnect_openconnect_setup_cmd_pipe'
  });

  log.log("openconnectlib version: " + myLib.openconnect_get_version());

  log.log("creating openconnect_info");
  var newVpnInfo = myLib.openconnect_vpninfo_new('vpntest', validate_peer_cert_cb, ref.NULL, process_auth_form_cb, write_progress_cb, ref.NULL);
  var ret = myLib.openconnect_init_ssl();
  var url = '103.242.72.92:8388';

  if ((ret = myLib.openconnect_parse_url(newVpnInfo, url)) != 0)
    log.log('Failed to parse the server URL ' + url);

  ret = myLib.openconnect_set_reported_os(newVpnInfo, 'win');
  ret = myLib.openconnect_set_protocol(newVpnInfo, 'anyconnect');

  if ((ret = myLib.openconnect_obtain_cookie(newVpnInfo)) != 0)
    log.log('Failed to obtain cookie');
  else
    log.log('Cookie obtained');

  if ((ret = myLib.openconnect_make_cstp_connection(newVpnInfo)) != 0)
    log.log('Failed to make CSTP connection');
  else
    log.log('CSTP connection established');

  if ((ret = myLib.openconnect_setup_tun_device(newVpnInfo, 'vpnc-script.js', ref.NULL)) != 0)
    log.log('Failed to setup the TUN device.');
  else
    log.log('TUN device set up');

  myLib.openconnect_mainloop.async(newVpnInfo, 300, 10, function(){
    log.log('param pam pam');
  });

  // Prevent garbage collection 
  process.on('exit', function () {
    write_progress_cb;
    validate_peer_cert_cb;
    process_auth_form_cb;
  });
}

// app.commandLine.appendSwitch('js-flags', '--max-old-space-size=4096');

app.on('ready', createWindow)

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit()
})

app.on('activate', function () {
  if (mainWindow === null) createWindow()
})
