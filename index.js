const express     = require('express');
const app         = express();
const bodyParser  = module.require('body-parser');

// Controllers
const webRoutes      = require('./controllers/routes/webRoutesController');


//Configuration
var port = process.env.PORT || 5000;

app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(bodyParser.json());
app.use('/auth', webRoutes);

app.listen(port, () => {
    console.log('Everything running, on port ' + port);
});

