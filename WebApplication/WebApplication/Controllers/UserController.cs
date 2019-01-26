using log4net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using WebApplication.Models;

namespace WebApplication.Controllers
{
    public class UserController : Controller
    {
        private ILog log = LogManager.GetLogger(typeof(UserController));
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
                    log.Info(usermodel.UserName + " already exists");
                    ViewBag.DuplicateMessage = "Username already exists";
                    return View("Add", new User());
                }

                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                byte[] sel = new byte[4];
                rng.GetBytes(sel);
                usermodel.Salt = Convert.ToBase64String(sel);
                usermodel.Password += usermodel.Salt;

                //hachage Password                     
                var crypt = new SHA256Managed();
                var hash = new StringBuilder();                      

                byte[] crypto = crypt.ComputeHash(Encoding.UTF8.GetBytes(usermodel.Password));
                foreach (byte theByte in crypto)
                {
                    hash.Append(theByte.ToString("x2"));
                }

                //change password to hash password                     
                usermodel.Password = hash.ToString();
                usermodel.ConfirmPassword = usermodel.Password;

                dbmodel.User.Add(usermodel);
                dbmodel.SaveChanges();
                log.Info(usermodel.UserName + " Success Registration");
                ViewBag.SuccessMessage = "Success Registration";
                return View(new User());
            }
        }
        [HttpPost]
        public ActionResult Login(User userModel)
        {
            //log.Info("msg");
            using (MyDataBaseEntities dbmodel = new MyDataBaseEntities())
            {
                User user1 = (from u in dbmodel.User where u.UserName.Equals(userModel.UserName) select u).FirstOrDefault();
                if (user1 == null)
                {
                    log.Info(userModel.UserName + " does not exist");
                    ViewBag.Error = "Username does not exist";
                    return View("Add", new User());
                }
                else
                {
                    var crypt = new SHA256Managed();
                    var hash = new StringBuilder();
                    userModel.Password += user1.Salt;
                    byte[] crypto = crypt.ComputeHash(Encoding.UTF8.GetBytes(userModel.Password));
                    foreach (byte theByte in crypto)
                    {
                        hash.Append(theByte.ToString("x2"));
                    }
                   
                    userModel.Password = hash.ToString();
                    if (user1.Password == userModel.Password)
                    {
                        log.Info(user1.UserName + " authentified");
                        ViewBag.SuccessMessage = "authentified";
                        return View("Add", new User());
                    }
                    else
                    {
                        log.Info(user1.UserName + " login with incorrect password");
                        ViewBag.Error = " incorrect password , try again ";
                        return View("Add", new User());
                    }
                }
            }
        }
    }
}