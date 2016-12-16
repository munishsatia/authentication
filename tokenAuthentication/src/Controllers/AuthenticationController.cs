using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace tokenAuthentication.Controllers
{
    public class AuthenticationController : Controller
    {
        [Route("api/[controller]")]
        [Authorize("Bearer")]
        public IActionResult Get()
        {
            return new OkResult();
        }
    }
}
