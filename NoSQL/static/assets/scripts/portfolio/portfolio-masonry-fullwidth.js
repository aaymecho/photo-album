// Cube Portfolio
var Portfolio = function() {
    "use strict";

    // Handle Portfolio Fullwidth
    var handlePortfolioMasonryFullwidth = function() {
        $('#portfolio-masonry-fullwidth').cubeportfolio({
            filters: '#portfolio-masonry-fullwidth-filter',
            layoutMode: 'mosaic',
            defaultFilter: '*',
            animationType: 'rotateRoom',
            gapHorizontal: 0,
            gapVertical: 0,
            gridAdjustment: 'responsive',
            mediaQueries: [{
                width: 1500,
                cols: 5
            }, {
                width: 1100,
                cols: 5
            }, {
                width: 800,
                cols: 4
            }, {
                width: 550,
                cols: 2
            }, {
                width: 320,
                cols: 1
            }],
            caption: ' ',
            displayType: 'bottomToTop',
            displayTypeSpeed: 100,

            // singlePage popup
            singlePageDelegate: '.cbp-singlePage',
            singlePageDeeplinking: true,
            singlePageStickyNavigation: true,
            singlePageCounter: '<div class="cbp-popup-singlePage-counter">{{current}} of {{total}}</div>',
            singlePageCallback: function(url, element) {
                // to update singlePage content use the following method: this.updateSinglePage(yourContent)
                var t = this;

                $.ajax({
                        url: url,
                        type: 'GET',
                        dataType: 'html',
                        timeout: 10000
                    })
                    .done(function(result) {
                        t.updateSinglePage(result);
                    })
                    .fail(function() {
                        t.updateSinglePage('AJAX Error! Please refresh the page!');
                    });
            },
        });
    }

    return {
        init: function() {
            handlePortfolioMasonryFullwidth(); // initial setup for portfolio fullwidth
        }
    }
}();

$(document).ready(function() {
    Portfolio.init();
});
