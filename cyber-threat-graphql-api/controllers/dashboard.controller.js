const Dashboard = require('../models/dashboard.model');

exports.getThreatDashboard = async (req, res, next) => {
  const currentPage = req.query.page || 1;
  const perPage = 2;

  try {
    const totalItems = await Dashboard.find().countDocuments();
    const posts = await Dashboard.find()
      .skip((currentPage - 1) * perPage)
      .limit(perPage);
    res.status(200).json({ posts, totalItems });
  } catch (error) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.addThreatEntry = (req, res, next) => {
  const error = validationResult(req);
  if (!error.isEmpty()) {
    const error = new Error('Validation failed, entered data is incorrect');
    error.statusCode = 422;
    throw error;
  }

  if (!req.file) {
    const error = new Error('No image provided');
    error.statusCode = 422;
    throw error;
  }

  const title = req.body.title;
  const content = req.body.content;
  const imageUrl = req.file.path.replace('\\', '/');
  let creator;

  const post = new Post({
    title: title,
    content: content,
    imageUrl: imageUrl,
    creator: req.userId,
  });
  post
    .save()
    .then((result) => {
      return User.findById(req.userId);
    })
    .then((user) => {
      if (!user) {
        const error = new Error('No user was found');
        error.statusCode = 422;
        throw error;
      }

      creator = user;
      user.posts.push(post);
      return user.save();
    })
    .then((result) => {
      res.status(201).json({
        message: 'Post created successfully!',
        post: result,
        creator: { _id: creator._id, name: creator.name },
      });
    })
    .catch((err) => {
      if (!err.statusCode) {
        err.statusCode = 500;
      }
      next(err);
    });
};

// exports.getPost = (req, res, next) => {
//   const postId = req.params.postId;
//   Post.findById(postId)
//     .then((post) => {
//       if (!post) {
//         const error = new Error('Could not find post.');
//         error.statusCode = 404;
//         throw error;
//       }
//       res.status(200).json({ message: 'Post fetched.', post: post });
//     })
//     .catch((err) => {
//       if (!err.statusCode) {
//         err.statusCode = 500;
//       }
//       next(err);
//     });
// };

// exports.updatePost = (req, res, next) => {
//   const errors = validationResult(req);
//   if (!errors.isEmpty()) {
//     const error = new Error('Validation failed, entered data is incorrect');
//     error.statusCode = 422;
//     throw error;
//   }

//   const postId = req.params.postId;
//   const title = req.body.title;
//   const content = req.body.content;
//   let imageUrl = req.body.image;

//   if (req.file) {
//     // imageUrl = req.file.path.replace('\\', '/');
//     imageUrl = req.file.path.replace(/\\/g, '/');
//   }
//   if (!imageUrl) {
//     const error = new Error('No file picked.');
//     error.statusCode = 404;
//     throw error;
//   }

//   Post.findById(postId)
//     .then((post) => {
//       if (!post) {
//         const error = new Error('Could not find post.');
//         error.statusCode = 404;
//         throw error;
//       }

//       if (imageUrl !== post.imageUrl) {
//         clearImage(post.imageUrl);
//       }
//       post.title = title;
//       post.content = content;
//       post.imageUrl = imageUrl;
//       return post.save();
//     })
//     .then((result) => {
//       res.status(200).json({ message: 'Post fetched.', post: result });
//     })
//     .catch((err) => {
//       if (!err.statusCode) {
//         err.statusCode = 500;
//       }
//       next(err);
//     });
// };

// exports.deletePost = (req, res, next) => {
//   const postId = req.params.postId;
//   Post.findById(postId)
//     .then((post) => {
//       if (!post) {
//         const error = new Error('Could not find post.');
//         error.statusCode = 404;
//         throw error;
//       }

//       clearImage(post.imageUrl);
//       return Post.findByIdAndDelete(postId);
//     })
//     .then((result) => {
//       res.status(200).json({ message: 'Deleted post.' });
//     })
//     .catch((err) => {
//       if (!err.statusCode) {
//         err.statusCode = 500;
//       }
//       next(err);
//     });
// };
