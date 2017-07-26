var smartnsf = require('../lib/passport-smartnsf');
var expect = require('chai').expect;

describe("SmartNSF", function() {
    describe('Module initialization', function() {
        it('Exports SmartNSF Strategy', function() {
            expect(smartnsf.SmartNSFStrategy).to.be.an('function');
        });
    });
    describe('Creating Strategy', function() {
        var errorType = new Error();
        var SmartNSFStrategy = smartnsf.SmartNSFStrategy;
        var fnCreateSmartNSFStrategy = function(options, verify, extractor) {
            new SmartNSFStrategy(options, verify, extractor);
        }
        it('No parameter in constructors throws exception', function() {
            expect(fnCreateSmartNSFStrategy).to.throw(/SmartNSF authentication/);
        });
    });
});