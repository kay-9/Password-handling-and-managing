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
        [HttpPost]
        public ActionResult Login(User userModel)
        {
            using (MyDataBaseEntities dbmodel = new MyDataBaseEntities())
            {
                User user1 = (from u in dbmodel.User where u.UserName.Equals(userModel.UserName) select u).FirstOrDefault();
                if (user1==null)
                {
                    ViewBag.Error = "Username does not exist";
                    return View("Add", new User());
                }
                else if (user1.Password == userModel.Password)
                {
                    ViewBag.SuccessMessage = "authentified";
                    return View("Add", new User());
                }
                else
                {
                    ViewBag.Error = " incorrect password , try again ";
                    return View("Add", new User());
                }
            }
        }
    }
}