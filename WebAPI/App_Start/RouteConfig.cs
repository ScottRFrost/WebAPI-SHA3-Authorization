using System.Web.Mvc;
using System.Web.Routing;

namespace Columbia_Sussex
{
    public class RouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");
            routes.IgnoreRoute(""); //Allow index.html to load
        }
    }
}
