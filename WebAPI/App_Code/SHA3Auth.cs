using System;
using System.Linq;
using System.Net;
using System.Net.Http;

namespace WebAPI
{
    public class SHA3Auth : System.Web.Http.AuthorizeAttribute
    {
        public override void OnAuthorization(System.Web.Http.Controllers.HttpActionContext actionContext)
        {
            var request = actionContext.Request;

            //Look for Authorization header
            if (!request.Headers.Contains("Authorization"))
            {
                actionContext.Response = request.CreateErrorResponse(HttpStatusCode.Unauthorized, "Authorization Header Required.");
                return;
            }
            
            //Split Username|UTC Date|Hash of url + localStorage.apikey + utcNumber
            var auth = request.Headers.GetValues("Authorization");
            var parts = auth.First().Split('|');
            if (parts.Length != 3)
            {
                actionContext.Response = request.CreateErrorResponse(HttpStatusCode.BadRequest, "Authorization Header Malformed.  It should be three pipe separated parts.");
                return;
            }

            //Make sure UTC date is +/- 15 minutes from current system time
            double utcTicks;
            if (!Double.TryParse(parts[1], out utcTicks))
            {
                actionContext.Response = request.CreateErrorResponse(HttpStatusCode.BadRequest, "Time not numeric.  Send as ticks since 1/1/1970.");
                return;
            }
            var utcdate = new DateTime(1970, 1, 1).AddMilliseconds(utcTicks);
            var timeskew = utcdate.Subtract(DateTime.UtcNow);
            if (timeskew.TotalMinutes > 15 || timeskew.TotalMinutes < -15)
            {
                actionContext.Response = request.CreateErrorResponse(HttpStatusCode.BadRequest, "Time too far from server time");
                return;
            }

            //Check vs API key in database
            var url = request.RequestUri.AbsolutePath;
            var utf8 = new System.Text.UTF8Encoding();
            var sha3 = new SHA3Managed(512);
            var hashed = sha3.ComputeHash(utf8.GetBytes(url + "test" + parts[1])); //Load the middle portion from database, after looking up the API Key by the username
            if (parts[2] != Convert.ToBase64String(hashed))
            {
                actionContext.Response = request.CreateErrorResponse(HttpStatusCode.Forbidden, "Bad API Key");
            }
        }
    }
}