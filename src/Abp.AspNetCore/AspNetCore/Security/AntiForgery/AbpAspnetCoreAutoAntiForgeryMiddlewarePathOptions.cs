using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace Abp.AspNetCore.Security.AntiForgery
{
    internal class AbpAspnetCoreAutoAntiForgeryMiddlewarePathOptions
    {
        public HttpMethod Method { get; set; }

        public string Path { get; set; }

        public PathMatchType PathMatchType { get; set; }
    }
}
