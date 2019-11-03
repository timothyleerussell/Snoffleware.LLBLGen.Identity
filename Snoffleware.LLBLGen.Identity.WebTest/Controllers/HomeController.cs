using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Snoffleware.LLBLGen.Identity.WebTest.Models;

namespace Snoffleware.LLBLGen.Identity.WebTest.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        [Authorize]
        public IActionResult Privacy()
        {
            return View();
        }
        [Authorize]
        public IActionResult Authorize()
        {
            return View("Authorize");
        }

        ////TODO: these role names should not have to uppercase here.
        ////something I'm doing in the RoleStore is screwing up default behavior
        ////which from Microsoft samples suggests these should be normally-cased names

        //[Authorize(Roles = "ADMINISTRATOR")]
        //public IActionResult AuthorizeRole()
        //{
        //    return View("AuthorizeRole");
        //}
        //[Authorize(Roles = "ADMINISTRATOR")]  //AND
        //[Authorize(Roles = "EDITOR")]
        //public IActionResult AuthorizeTwoRoles()
        //{
        //    return View("AuthorizeTwoRoles");
        //}
        //[Authorize(Roles = "ADMINISTRATOR,EDITOR")]   //OR
        //public IActionResult AuthorizeAdministratorOrEditor()
        //{
        //    return View("AuthorizeAdministratorOrEditor");
        //}
        //[Authorize]
        //public IActionResult AuthorizedUserShowClaims()
        //{
        //    return View("AuthorizedUserShowClaims");
        //}
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
