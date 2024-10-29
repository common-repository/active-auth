// create form to submit
document.write('<form action="" id="2fa-form" method="post"><input type="hidden" id="2fa-verify" name="2fa-verify" value="" /></form>');
// Message to the server
var srv = encodeURIComponent(ACASecret.split(':')[1]);
// Message to the app
var app = encodeURIComponent(ACASecret.split(':')[0]);
var myframe = document.getElementById('acaframe');
myframe.src =  'https://' + ACAServer + ':9100/sys/index.wcgp?skin=ACA&srv=' + srv + "&acaaccount=" + ACAAccount;
if (typeof ACAcss != 'undefined') {
    myframe.src =  myframe.src + "&css=" + ACAcss;
}
// Create IE + others compatible event handler
var eventMethod = window.addEventListener ? "addEventListener" : "attachEvent";
var eventeHandler = window[eventMethod];
var messageEvent = eventMethod == "attachEvent" ? "onmessage" : "message";

// Listen to message from child window
eventeHandler(messageEvent,function(e) {
    if (e.origin == 'https://' + ACAServer + ':9100') {
        var input = document.getElementById('2fa-verify');
        var form = document.getElementById('2fa-form');
        form.action = ACAAction;
        input.value = e.data + ":" + decodeURI(app).replace(/%3D/gi, "=");
        form.submit();
    };
},false);