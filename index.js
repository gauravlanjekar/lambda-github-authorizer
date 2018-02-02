'use strict';

var lib = require('./lib');
var fs = require('fs');

// Lambda function index.handler - thin wrapper around lib.authenticate
module.exports.handler = function( event, context ) {
  lib.authenticate( event )
    .then( context.succeed )
    .catch( err => {
      if ( ! err ) context.fail( "Unhandled error case" );
//      if ( err.message ) context.fail( err.message );
      context.fail( err );
    });
};
