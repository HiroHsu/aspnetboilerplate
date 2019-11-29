using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Abp.AspNetCore.Security.AntiForgery
{
    public class AbpAspnetCoreAutoAntiForgeryMiddlewareOptions
    {
        internal List<Func<HttpRequest, bool>> IsPathMatchPredicateFunctions { get; set; }

        internal List<AbpAspnetCoreAutoAntiForgeryMiddlewarePathOptions> Paths { get; set; }

        public AbpAspnetCoreAutoAntiForgeryMiddlewareOptions()
        {
            IsPathMatchPredicateFunctions = new List<Func<HttpRequest, bool>>();
            Paths = new List<AbpAspnetCoreAutoAntiForgeryMiddlewarePathOptions>();
        }

        /// <summary>
        /// If path matches with a request, anti-forgery token will be added to the request automatically
        /// </summary>
        /// <param name="method"></param>
        /// <param name="path"></param>
        /// <param name="pathMatchType"></param>
        public void AddPath(HttpMethod method, string path, PathMatchType pathMatchType = PathMatchType.ExactMatch)
        {
            Paths.Add(new AbpAspnetCoreAutoAntiForgeryMiddlewarePathOptions()
            {
                Method = method,
                Path = path.Trim(),
                PathMatchType = pathMatchType
            });
        }

        /// <summary>
        /// If predicate returns true for a request, anti-forgery token will be added to the request automatically
        /// </summary>
        /// <param name="predicate"></param>
        public void AddPredicate(Func<HttpRequest, bool> predicate)
        {
            IsPathMatchPredicateFunctions.Add(predicate);
        }
    }
}
