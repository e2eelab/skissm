// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/CreateGroupMsg.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_skissm_2fCreateGroupMsg_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_skissm_2fCreateGroupMsg_2eproto

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
#include "skissm/E2eeAddress.pb.h"
#include "skissm/GroupMember.pb.h"
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_skissm_2fCreateGroupMsg_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_skissm_2fCreateGroupMsg_2eproto {
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
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fCreateGroupMsg_2eproto;
namespace skissm {
class CreateGroupMsg;
struct CreateGroupMsgDefaultTypeInternal;
extern CreateGroupMsgDefaultTypeInternal _CreateGroupMsg_default_instance_;
}  // namespace skissm
PROTOBUF_NAMESPACE_OPEN
template<> ::skissm::CreateGroupMsg* Arena::CreateMaybeMessage<::skissm::CreateGroupMsg>(Arena*);
PROTOBUF_NAMESPACE_CLOSE
namespace skissm {

// ===================================================================

class CreateGroupMsg final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:skissm.CreateGroupMsg) */ {
 public:
  inline CreateGroupMsg() : CreateGroupMsg(nullptr) {}
  ~CreateGroupMsg() override;
  explicit constexpr CreateGroupMsg(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  CreateGroupMsg(const CreateGroupMsg& from);
  CreateGroupMsg(CreateGroupMsg&& from) noexcept
    : CreateGroupMsg() {
    *this = ::std::move(from);
  }

  inline CreateGroupMsg& operator=(const CreateGroupMsg& from) {
    CopyFrom(from);
    return *this;
  }
  inline CreateGroupMsg& operator=(CreateGroupMsg&& from) noexcept {
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
  static const CreateGroupMsg& default_instance() {
    return *internal_default_instance();
  }
  static inline const CreateGroupMsg* internal_default_instance() {
    return reinterpret_cast<const CreateGroupMsg*>(
               &_CreateGroupMsg_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(CreateGroupMsg& a, CreateGroupMsg& b) {
    a.Swap(&b);
  }
  inline void Swap(CreateGroupMsg* other) {
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
  void UnsafeArenaSwap(CreateGroupMsg* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  CreateGroupMsg* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<CreateGroupMsg>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const CreateGroupMsg& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom(const CreateGroupMsg& from);
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
  void InternalSwap(CreateGroupMsg* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "skissm.CreateGroupMsg";
  }
  protected:
  explicit CreateGroupMsg(::PROTOBUF_NAMESPACE_ID::Arena* arena,
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
    kGroupMembersFieldNumber = 3,
    kE2EePackIdFieldNumber = 1,
    kGroupNameFieldNumber = 4,
    kSenderAddressFieldNumber = 2,
    kGroupAddressFieldNumber = 5,
  };
  // repeated .skissm.GroupMember group_members = 3;
  int group_members_size() const;
  private:
  int _internal_group_members_size() const;
  public:
  void clear_group_members();
  ::skissm::GroupMember* mutable_group_members(int index);
  ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::skissm::GroupMember >*
      mutable_group_members();
  private:
  const ::skissm::GroupMember& _internal_group_members(int index) const;
  ::skissm::GroupMember* _internal_add_group_members();
  public:
  const ::skissm::GroupMember& group_members(int index) const;
  ::skissm::GroupMember* add_group_members();
  const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::skissm::GroupMember >&
      group_members() const;

  // string e2ee_pack_id = 1;
  void clear_e2ee_pack_id();
  const std::string& e2ee_pack_id() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_e2ee_pack_id(ArgT0&& arg0, ArgT... args);
  std::string* mutable_e2ee_pack_id();
  PROTOBUF_NODISCARD std::string* release_e2ee_pack_id();
  void set_allocated_e2ee_pack_id(std::string* e2ee_pack_id);
  private:
  const std::string& _internal_e2ee_pack_id() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_e2ee_pack_id(const std::string& value);
  std::string* _internal_mutable_e2ee_pack_id();
  public:

  // string group_name = 4;
  void clear_group_name();
  const std::string& group_name() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_group_name(ArgT0&& arg0, ArgT... args);
  std::string* mutable_group_name();
  PROTOBUF_NODISCARD std::string* release_group_name();
  void set_allocated_group_name(std::string* group_name);
  private:
  const std::string& _internal_group_name() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_group_name(const std::string& value);
  std::string* _internal_mutable_group_name();
  public:

  // .skissm.E2eeAddress sender_address = 2;
  bool has_sender_address() const;
  private:
  bool _internal_has_sender_address() const;
  public:
  void clear_sender_address();
  const ::skissm::E2eeAddress& sender_address() const;
  PROTOBUF_NODISCARD ::skissm::E2eeAddress* release_sender_address();
  ::skissm::E2eeAddress* mutable_sender_address();
  void set_allocated_sender_address(::skissm::E2eeAddress* sender_address);
  private:
  const ::skissm::E2eeAddress& _internal_sender_address() const;
  ::skissm::E2eeAddress* _internal_mutable_sender_address();
  public:
  void unsafe_arena_set_allocated_sender_address(
      ::skissm::E2eeAddress* sender_address);
  ::skissm::E2eeAddress* unsafe_arena_release_sender_address();

  // .skissm.E2eeAddress group_address = 5;
  bool has_group_address() const;
  private:
  bool _internal_has_group_address() const;
  public:
  void clear_group_address();
  const ::skissm::E2eeAddress& group_address() const;
  PROTOBUF_NODISCARD ::skissm::E2eeAddress* release_group_address();
  ::skissm::E2eeAddress* mutable_group_address();
  void set_allocated_group_address(::skissm::E2eeAddress* group_address);
  private:
  const ::skissm::E2eeAddress& _internal_group_address() const;
  ::skissm::E2eeAddress* _internal_mutable_group_address();
  public:
  void unsafe_arena_set_allocated_group_address(
      ::skissm::E2eeAddress* group_address);
  ::skissm::E2eeAddress* unsafe_arena_release_group_address();

  // @@protoc_insertion_point(class_scope:skissm.CreateGroupMsg)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::skissm::GroupMember > group_members_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr e2ee_pack_id_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr group_name_;
  ::skissm::E2eeAddress* sender_address_;
  ::skissm::E2eeAddress* group_address_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_skissm_2fCreateGroupMsg_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// CreateGroupMsg

// string e2ee_pack_id = 1;
inline void CreateGroupMsg::clear_e2ee_pack_id() {
  e2ee_pack_id_.ClearToEmpty();
}
inline const std::string& CreateGroupMsg::e2ee_pack_id() const {
  // @@protoc_insertion_point(field_get:skissm.CreateGroupMsg.e2ee_pack_id)
  return _internal_e2ee_pack_id();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void CreateGroupMsg::set_e2ee_pack_id(ArgT0&& arg0, ArgT... args) {
 
 e2ee_pack_id_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:skissm.CreateGroupMsg.e2ee_pack_id)
}
inline std::string* CreateGroupMsg::mutable_e2ee_pack_id() {
  std::string* _s = _internal_mutable_e2ee_pack_id();
  // @@protoc_insertion_point(field_mutable:skissm.CreateGroupMsg.e2ee_pack_id)
  return _s;
}
inline const std::string& CreateGroupMsg::_internal_e2ee_pack_id() const {
  return e2ee_pack_id_.Get();
}
inline void CreateGroupMsg::_internal_set_e2ee_pack_id(const std::string& value) {
  
  e2ee_pack_id_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* CreateGroupMsg::_internal_mutable_e2ee_pack_id() {
  
  return e2ee_pack_id_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* CreateGroupMsg::release_e2ee_pack_id() {
  // @@protoc_insertion_point(field_release:skissm.CreateGroupMsg.e2ee_pack_id)
  return e2ee_pack_id_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void CreateGroupMsg::set_allocated_e2ee_pack_id(std::string* e2ee_pack_id) {
  if (e2ee_pack_id != nullptr) {
    
  } else {
    
  }
  e2ee_pack_id_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), e2ee_pack_id,
      GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (e2ee_pack_id_.IsDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited())) {
    e2ee_pack_id_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:skissm.CreateGroupMsg.e2ee_pack_id)
}

// .skissm.E2eeAddress sender_address = 2;
inline bool CreateGroupMsg::_internal_has_sender_address() const {
  return this != internal_default_instance() && sender_address_ != nullptr;
}
inline bool CreateGroupMsg::has_sender_address() const {
  return _internal_has_sender_address();
}
inline const ::skissm::E2eeAddress& CreateGroupMsg::_internal_sender_address() const {
  const ::skissm::E2eeAddress* p = sender_address_;
  return p != nullptr ? *p : reinterpret_cast<const ::skissm::E2eeAddress&>(
      ::skissm::_E2eeAddress_default_instance_);
}
inline const ::skissm::E2eeAddress& CreateGroupMsg::sender_address() const {
  // @@protoc_insertion_point(field_get:skissm.CreateGroupMsg.sender_address)
  return _internal_sender_address();
}
inline void CreateGroupMsg::unsafe_arena_set_allocated_sender_address(
    ::skissm::E2eeAddress* sender_address) {
  if (GetArenaForAllocation() == nullptr) {
    delete reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(sender_address_);
  }
  sender_address_ = sender_address;
  if (sender_address) {
    
  } else {
    
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:skissm.CreateGroupMsg.sender_address)
}
inline ::skissm::E2eeAddress* CreateGroupMsg::release_sender_address() {
  
  ::skissm::E2eeAddress* temp = sender_address_;
  sender_address_ = nullptr;
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
inline ::skissm::E2eeAddress* CreateGroupMsg::unsafe_arena_release_sender_address() {
  // @@protoc_insertion_point(field_release:skissm.CreateGroupMsg.sender_address)
  
  ::skissm::E2eeAddress* temp = sender_address_;
  sender_address_ = nullptr;
  return temp;
}
inline ::skissm::E2eeAddress* CreateGroupMsg::_internal_mutable_sender_address() {
  
  if (sender_address_ == nullptr) {
    auto* p = CreateMaybeMessage<::skissm::E2eeAddress>(GetArenaForAllocation());
    sender_address_ = p;
  }
  return sender_address_;
}
inline ::skissm::E2eeAddress* CreateGroupMsg::mutable_sender_address() {
  ::skissm::E2eeAddress* _msg = _internal_mutable_sender_address();
  // @@protoc_insertion_point(field_mutable:skissm.CreateGroupMsg.sender_address)
  return _msg;
}
inline void CreateGroupMsg::set_allocated_sender_address(::skissm::E2eeAddress* sender_address) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArenaForAllocation();
  if (message_arena == nullptr) {
    delete reinterpret_cast< ::PROTOBUF_NAMESPACE_ID::MessageLite*>(sender_address_);
  }
  if (sender_address) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
        ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper<
            ::PROTOBUF_NAMESPACE_ID::MessageLite>::GetOwningArena(
                reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(sender_address));
    if (message_arena != submessage_arena) {
      sender_address = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, sender_address, submessage_arena);
    }
    
  } else {
    
  }
  sender_address_ = sender_address;
  // @@protoc_insertion_point(field_set_allocated:skissm.CreateGroupMsg.sender_address)
}

// repeated .skissm.GroupMember group_members = 3;
inline int CreateGroupMsg::_internal_group_members_size() const {
  return group_members_.size();
}
inline int CreateGroupMsg::group_members_size() const {
  return _internal_group_members_size();
}
inline ::skissm::GroupMember* CreateGroupMsg::mutable_group_members(int index) {
  // @@protoc_insertion_point(field_mutable:skissm.CreateGroupMsg.group_members)
  return group_members_.Mutable(index);
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::skissm::GroupMember >*
CreateGroupMsg::mutable_group_members() {
  // @@protoc_insertion_point(field_mutable_list:skissm.CreateGroupMsg.group_members)
  return &group_members_;
}
inline const ::skissm::GroupMember& CreateGroupMsg::_internal_group_members(int index) const {
  return group_members_.Get(index);
}
inline const ::skissm::GroupMember& CreateGroupMsg::group_members(int index) const {
  // @@protoc_insertion_point(field_get:skissm.CreateGroupMsg.group_members)
  return _internal_group_members(index);
}
inline ::skissm::GroupMember* CreateGroupMsg::_internal_add_group_members() {
  return group_members_.Add();
}
inline ::skissm::GroupMember* CreateGroupMsg::add_group_members() {
  ::skissm::GroupMember* _add = _internal_add_group_members();
  // @@protoc_insertion_point(field_add:skissm.CreateGroupMsg.group_members)
  return _add;
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::skissm::GroupMember >&
CreateGroupMsg::group_members() const {
  // @@protoc_insertion_point(field_list:skissm.CreateGroupMsg.group_members)
  return group_members_;
}

// string group_name = 4;
inline void CreateGroupMsg::clear_group_name() {
  group_name_.ClearToEmpty();
}
inline const std::string& CreateGroupMsg::group_name() const {
  // @@protoc_insertion_point(field_get:skissm.CreateGroupMsg.group_name)
  return _internal_group_name();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void CreateGroupMsg::set_group_name(ArgT0&& arg0, ArgT... args) {
 
 group_name_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:skissm.CreateGroupMsg.group_name)
}
inline std::string* CreateGroupMsg::mutable_group_name() {
  std::string* _s = _internal_mutable_group_name();
  // @@protoc_insertion_point(field_mutable:skissm.CreateGroupMsg.group_name)
  return _s;
}
inline const std::string& CreateGroupMsg::_internal_group_name() const {
  return group_name_.Get();
}
inline void CreateGroupMsg::_internal_set_group_name(const std::string& value) {
  
  group_name_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* CreateGroupMsg::_internal_mutable_group_name() {
  
  return group_name_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* CreateGroupMsg::release_group_name() {
  // @@protoc_insertion_point(field_release:skissm.CreateGroupMsg.group_name)
  return group_name_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void CreateGroupMsg::set_allocated_group_name(std::string* group_name) {
  if (group_name != nullptr) {
    
  } else {
    
  }
  group_name_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), group_name,
      GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (group_name_.IsDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited())) {
    group_name_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:skissm.CreateGroupMsg.group_name)
}

// .skissm.E2eeAddress group_address = 5;
inline bool CreateGroupMsg::_internal_has_group_address() const {
  return this != internal_default_instance() && group_address_ != nullptr;
}
inline bool CreateGroupMsg::has_group_address() const {
  return _internal_has_group_address();
}
inline const ::skissm::E2eeAddress& CreateGroupMsg::_internal_group_address() const {
  const ::skissm::E2eeAddress* p = group_address_;
  return p != nullptr ? *p : reinterpret_cast<const ::skissm::E2eeAddress&>(
      ::skissm::_E2eeAddress_default_instance_);
}
inline const ::skissm::E2eeAddress& CreateGroupMsg::group_address() const {
  // @@protoc_insertion_point(field_get:skissm.CreateGroupMsg.group_address)
  return _internal_group_address();
}
inline void CreateGroupMsg::unsafe_arena_set_allocated_group_address(
    ::skissm::E2eeAddress* group_address) {
  if (GetArenaForAllocation() == nullptr) {
    delete reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(group_address_);
  }
  group_address_ = group_address;
  if (group_address) {
    
  } else {
    
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:skissm.CreateGroupMsg.group_address)
}
inline ::skissm::E2eeAddress* CreateGroupMsg::release_group_address() {
  
  ::skissm::E2eeAddress* temp = group_address_;
  group_address_ = nullptr;
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
inline ::skissm::E2eeAddress* CreateGroupMsg::unsafe_arena_release_group_address() {
  // @@protoc_insertion_point(field_release:skissm.CreateGroupMsg.group_address)
  
  ::skissm::E2eeAddress* temp = group_address_;
  group_address_ = nullptr;
  return temp;
}
inline ::skissm::E2eeAddress* CreateGroupMsg::_internal_mutable_group_address() {
  
  if (group_address_ == nullptr) {
    auto* p = CreateMaybeMessage<::skissm::E2eeAddress>(GetArenaForAllocation());
    group_address_ = p;
  }
  return group_address_;
}
inline ::skissm::E2eeAddress* CreateGroupMsg::mutable_group_address() {
  ::skissm::E2eeAddress* _msg = _internal_mutable_group_address();
  // @@protoc_insertion_point(field_mutable:skissm.CreateGroupMsg.group_address)
  return _msg;
}
inline void CreateGroupMsg::set_allocated_group_address(::skissm::E2eeAddress* group_address) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArenaForAllocation();
  if (message_arena == nullptr) {
    delete reinterpret_cast< ::PROTOBUF_NAMESPACE_ID::MessageLite*>(group_address_);
  }
  if (group_address) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
        ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper<
            ::PROTOBUF_NAMESPACE_ID::MessageLite>::GetOwningArena(
                reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(group_address));
    if (message_arena != submessage_arena) {
      group_address = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, group_address, submessage_arena);
    }
    
  } else {
    
  }
  group_address_ = group_address;
  // @@protoc_insertion_point(field_set_allocated:skissm.CreateGroupMsg.group_address)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__

// @@protoc_insertion_point(namespace_scope)

}  // namespace skissm

// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_skissm_2fCreateGroupMsg_2eproto