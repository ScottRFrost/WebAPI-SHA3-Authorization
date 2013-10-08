WebAPI-SHA3-Authorization
=========================

Custom authorization for WebAPI by signing each request with a SHA3 hash in the format:
  username|UTC Time Number|SHA3 Hash of URL + API Key + UTC Time Number (concatenated, not added).

Sample client code is AngularJS 1.2.x and loads username and API key from localstorage,
but it would work just as well with jQuery or even plain Javascript.
