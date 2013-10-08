using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace WebAPI.Controllers
{
    
    public class TimeController : ApiController
    {
        [SHA3Auth]
        public double Get()
        {
            return Math.Floor(DateTime.Now.Subtract(new DateTime(1970, 1, 1, 0, 0, 0)).TotalMilliseconds);
        }
    }
}
