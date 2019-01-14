﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using WebApplication.Models;

namespace WebApplication.Controllers
{
    public class UserController : Controller
    {
        // GET: User
        public ActionResult Index()
        {
            return View();
        }
        [HttpGet]
        public ActionResult Add(int id = 0)
        {
            User usermodel1 = new User();
            return View(usermodel1);
        }
        [HttpPost]
        public ActionResult Add(User usermodel)
        {
            using (MyDataBaseEntities dbmodel = new MyDataBaseEntities())
            {
                if (dbmodel.User.Any(x => x.UserName == usermodel.UserName))
                {
                    ViewBag.DuplicateMessage = "Username already exists";
                    return View("Add", new User());
                }

                dbmodel.User.Add(usermodel);
                dbmodel.SaveChanges();
                ViewBag.SuccessMessage = "Success Registration";
                return View(new User());
            }
        }
    }
}