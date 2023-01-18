// maybeFormatFault.js
// ------------------------------------------------------------------
//
// maybe format a fault message if one is not present.
//
// created: Tue Jan 26 14:07:19 2016
// last saved: <2023-January-17 16:46:13>

var handled = context.getVariable('fault_handled');
if ( ! handled ) {
  var error = response.content.asJSON.error;
  var t = typeof error;
  print('typeof error: ' + t);
  if (t == 'undefined') {
    response.content = '{"error": "unknown"}';
  }
  context.setVariable('fault_handled', true);
}
