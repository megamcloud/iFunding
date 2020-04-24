const jwt = require("jsonwebtoken");
const asyncHandler = require("./async");
const ErrorResponse = require("../utils/errorResponse");
const User = require("../models/User");

// Protect Routes
exports.protect = asyncHandler(async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    // set token from authorization header
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies.token) {
    // set token from cookies
    token = req.cookies.token;
  }

  // Make sure token exists
  if (!token) {
    return next(new ErrorResponse("Not Authorized to access this route.", 401));
  }

  try {
    // Verify Token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = await User.findById(decoded.id);

    if (!req.user) {
      return next(
        new ErrorResponse(`User with id ${decoded.id} not found.`, 404)
      );
    }

    next();
  } catch (err) {
    return next(new ErrorResponse("Not Authorized to access this route.", 401));
  }
});

exports.authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new ErrorResponse(
          `User role ${req.user.role} is not authorized to access this route`,
          403
        )
      );
    }
    next();
  };
};
