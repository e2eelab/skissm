// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/SendOne2oneMsgRequest.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_skissm_2fSendOne2oneMsgRequest_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_skissm_2fSendOne2oneMsgRequest_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3019000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3019004 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/metadata_lite.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
#include "skissm/E2eeMsg.pb.h"
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_skissm_2fSendOne2oneMsgRequest_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_skissm_2fSendOne2oneMsgRequest_2eproto {
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTableField entries[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::AuxiliaryParseTableField aux[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTable schema[1]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::FieldMetadata field_metadata[];
  static const ::PROTOBUF_NAMESPACE_ID::internal::SerializationTable serialization_table[];
  static const uint32_t offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fSendOne2oneMsgRequest_2eproto;
namespace skissm {
class SendOne2oneMsgRequest;
struct SendOne2oneMsgRequestDefaultTypeInternal;
extern SendOne2oneMsgRequestDefaultTypeInternal _SendOne2oneMsgRequest_default_instance_;
}  // namespace skissm
PROTOBUF_NAMESPACE_OPEN
template<> ::skissm::SendOne2oneMsgRequest* Arena::CreateMaybeMessage<::skissm::SendOne2oneMsgRequest>(Arena*);
PROTOBUF_NAMESPACE_CLOSE
namespace skissm {

// ===================================================================

class SendOne2oneMsgRequest final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:skissm.SendOne2oneMsgRequest) */ {
 public:
  inline SendOne2oneMsgRequest() : SendOne2oneMsgRequest(nullptr) {}
  ~SendOne2oneMsgRequest() override;
  explicit constexpr SendOne2oneMsgRequest(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  SendOne2oneMsgRequest(const SendOne2oneMsgRequest& from);
  SendOne2oneMsgRequest(SendOne2oneMsgRequest&& from) noexcept
    : SendOne2oneMsgRequest() {
    *this = ::std::move(from);
  }

  inline SendOne2oneMsgRequest& operator=(const SendOne2oneMsgRequest& from) {
    CopyFrom(from);
    return *this;
  }
  inline SendOne2oneMsgRequest& operator=(SendOne2oneMsgRequest&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const SendOne2oneMsgRequest& default_instance() {
    return *internal_default_instance();
  }
  static inline const SendOne2oneMsgRequest* internal_default_instance() {
    return reinterpret_cast<const SendOne2oneMsgRequest*>(
               &_SendOne2oneMsgRequest_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(SendOne2oneMsgRequest& a, SendOne2oneMsgRequest& b) {
    a.Swap(&b);
  }
  inline void Swap(SendOne2oneMsgRequest* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(SendOne2oneMsgRequest* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  SendOne2oneMsgRequest* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<SendOne2oneMsgRequest>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const SendOne2oneMsgRequest& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom(const SendOne2oneMsgRequest& from);
  private:
  static void MergeImpl(::PROTOBUF_NAMESPACE_ID::Message* to, const ::PROTOBUF_NAMESPACE_ID::Message& from);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  uint8_t* _InternalSerialize(
      uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(SendOne2oneMsgRequest* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "skissm.SendOne2oneMsgRequest";
  }
  protected:
  explicit SendOne2oneMsgRequest(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kMsgFieldNumber = 1,
  };
  // .skissm.E2eeMsg msg = 1;
  bool has_msg() const;
  private:
  bool _internal_has_msg() const;
  public:
  void clear_msg();
  const ::skissm::E2eeMsg& msg() const;
  PROTOBUF_NODISCARD ::skissm::E2eeMsg* release_msg();
  ::skissm::E2eeMsg* mutable_msg();
  void set_allocated_msg(::skissm::E2eeMsg* msg);
  private:
  const ::skissm::E2eeMsg& _internal_msg() const;
  ::skissm::E2eeMsg* _internal_mutable_msg();
  public:
  void unsafe_arena_set_allocated_msg(
      ::skissm::E2eeMsg* msg);
  ::skissm::E2eeMsg* unsafe_arena_release_msg();

  // @@protoc_insertion_point(class_scope:skissm.SendOne2oneMsgRequest)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  ::skissm::E2eeMsg* msg_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_skissm_2fSendOne2oneMsgRequest_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// SendOne2oneMsgRequest

// .skissm.E2eeMsg msg = 1;
inline bool SendOne2oneMsgRequest::_internal_has_msg() const {
  return this != internal_default_instance() && msg_ != nullptr;
}
inline bool SendOne2oneMsgRequest::has_msg() const {
  return _internal_has_msg();
}
inline const ::skissm::E2eeMsg& SendOne2oneMsgRequest::_internal_msg() const {
  const ::skissm::E2eeMsg* p = msg_;
  return p != nullptr ? *p : reinterpret_cast<const ::skissm::E2eeMsg&>(
      ::skissm::_E2eeMsg_default_instance_);
}
inline const ::skissm::E2eeMsg& SendOne2oneMsgRequest::msg() const {
  // @@protoc_insertion_point(field_get:skissm.SendOne2oneMsgRequest.msg)
  return _internal_msg();
}
inline void SendOne2oneMsgRequest::unsafe_arena_set_allocated_msg(
    ::skissm::E2eeMsg* msg) {
  if (GetArenaForAllocation() == nullptr) {
    delete reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(msg_);
  }
  msg_ = msg;
  if (msg) {
    
  } else {
    
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:skissm.SendOne2oneMsgRequest.msg)
}
inline ::skissm::E2eeMsg* SendOne2oneMsgRequest::release_msg() {
  
  ::skissm::E2eeMsg* temp = msg_;
  msg_ = nullptr;
#ifdef PROTOBUF_FORCE_COPY_IN_RELEASE
  auto* old =  reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(temp);
  temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
  if (GetArenaForAllocation() == nullptr) { delete old; }
#else  // PROTOBUF_FORCE_COPY_IN_RELEASE
  if (GetArenaForAllocation() != nullptr) {
    temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
  }
#endif  // !PROTOBUF_FORCE_COPY_IN_RELEASE
  return temp;
}
inline ::skissm::E2eeMsg* SendOne2oneMsgRequest::unsafe_arena_release_msg() {
  // @@protoc_insertion_point(field_release:skissm.SendOne2oneMsgRequest.msg)
  
  ::skissm::E2eeMsg* temp = msg_;
  msg_ = nullptr;
  return temp;
}
inline ::skissm::E2eeMsg* SendOne2oneMsgRequest::_internal_mutable_msg() {
  
  if (msg_ == nullptr) {
    auto* p = CreateMaybeMessage<::skissm::E2eeMsg>(GetArenaForAllocation());
    msg_ = p;
  }
  return msg_;
}
inline ::skissm::E2eeMsg* SendOne2oneMsgRequest::mutable_msg() {
  ::skissm::E2eeMsg* _msg = _internal_mutable_msg();
  // @@protoc_insertion_point(field_mutable:skissm.SendOne2oneMsgRequest.msg)
  return _msg;
}
inline void SendOne2oneMsgRequest::set_allocated_msg(::skissm::E2eeMsg* msg) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArenaForAllocation();
  if (message_arena == nullptr) {
    delete reinterpret_cast< ::PROTOBUF_NAMESPACE_ID::MessageLite*>(msg_);
  }
  if (msg) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
        ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper<
            ::PROTOBUF_NAMESPACE_ID::MessageLite>::GetOwningArena(
                reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(msg));
    if (message_arena != submessage_arena) {
      msg = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, msg, submessage_arena);
    }
    
  } else {
    
  }
  msg_ = msg;
  // @@protoc_insertion_point(field_set_allocated:skissm.SendOne2oneMsgRequest.msg)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__

// @@protoc_insertion_point(namespace_scope)

}  // namespace skissm

// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_skissm_2fSendOne2oneMsgRequest_2eproto