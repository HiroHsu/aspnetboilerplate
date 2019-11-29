using System;
using System.Linq;
using System.Net.Http;
using Abp.Extensions;
using Abp.Web.Security.AntiForgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Abp.AspNetCore.Security.AntiForgery
{
    public static class AbpAspnetCoreAutoAntiForgeryMiddleware
    {
        /// <summary>
        /// Automatically adds anti-forgery cookie to matched requests 
        /// </summary>
        /// <param name="app"></param>
        /// <returns></returns>
        public static IApplicationBuilder UseAbpAutoAntiForgeryMiddleware(this IApplicationBuilder app, Action<AbpAspnetCoreAutoAntiForgeryMiddlewareOptions> setupAction)
        {
            if (setupAction == null)
            {
                return app;
            }

            var options = new AbpAspnetCoreAutoAntiForgeryMiddlewareOptions();
            setupAction(options);

            app.Use(async (context, next) =>
            {
                if (IsPredicateMatch(context.Request, options) || IsPathMatch(context.Request, options))
                {
                    context.RequestServices.GetRequiredService<IAbpAntiForgeryManager>().SetCookie(context);
                }

                await next.Invoke();
            });

            return app;
        }

        private static bool IsPredicateMatch(HttpRequest request, AbpAspnetCoreAutoAntiForgeryMiddlewareOptions option)
        {
            return option.IsPathMatchPredicateFunctions?.Any(f => f.Invoke(request)) ?? false;
        }

        private static bool IsPathMatch(HttpRequest request, AbpAspnetCoreAutoAntiForgeryMiddlewareOptions option)
        {
            if (!request.Path.HasValue)
            {
                return false;
            }

            foreach (var pathOption in option.Paths)
            {
                if (request.Method != pathOption.Method.ToString())
                {
                    continue;
                }


                switch (pathOption.PathMatchType)
                {
                    case PathMatchType.ExactMatch when request.Path.Value == pathOption.Path.EnsureStartsWith('/'):
                    case PathMatchType.StartWith when request.Path.Value.StartsWith(pathOption.Path.EnsureStartsWith('/')):
                        return true;
                }
            }

            return false;
        }
    }
}
