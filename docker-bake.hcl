variable "IMAGE" {
  default = "gasa:local"
}

group "default" {
  targets = ["gasa"]
}

target "gasa" {
  context = "."
  dockerfile = "Dockerfile"
  tags = [IMAGE]
}
